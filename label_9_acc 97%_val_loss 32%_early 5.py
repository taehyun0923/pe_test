# 설치 (최초 1회만 실행)
!pip install -q transformers datasets openpyxl

# Google Drive 마운트
from google.colab import drive
drive.mount('/content/drive')

# 라이브러리 임포트
import os
import pandas as pd
import torch
import numpy as np
from torch.utils.data import Dataset
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report
from transformers import (
    BertTokenizer, BertForSequenceClassification, Trainer, TrainingArguments,
    TrainerCallback
)
from datasets import load_metric

# 엑셀 파일 경로 설정
file_path = "/content/drive/MyDrive/privacy_law5_deduplicated.xlsx"

# 라벨 매핑 정의
label_map = {
    0: "초상권 침해",
    1: "동의 없는 개인정보 수집",
    2: "제3자 무단 제공",
    3: "CCTV 과잉촬영",
    4: "정보 유출",
    5: "파기 미이행",
    6: "계정/비밀번호 관련 문제",
    7: "개인정보 열람·정정 요구 거부"
}
label_map_str2int = {v: k for k, v in label_map.items()}

# 엑셀 로딩 및 전처리
df = pd.read_excel(file_path)
df['label'] = df['label'].map(label_map_str2int)

# 라벨별 454개 균등 추출
balanced_df = df.groupby('label').sample(n=454, random_state=42).reset_index(drop=True)
data = balanced_df[['case', 'label']].values.tolist()
train_texts, val_texts, train_labels, val_labels = train_test_split(
    [x[0] for x in data], [x[1] for x in data], test_size=0.2, random_state=42
)

# Dataset 정의
class LegalDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len=64):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        encoding = self.tokenizer(
            self.texts[idx],
            max_length=self.max_len,
            padding='max_length',
            truncation=True,
            return_tensors='pt'
        )
        return {
            'input_ids': encoding['input_ids'].squeeze(),
            'attention_mask': encoding['attention_mask'].squeeze(),
            'labels': torch.tensor(self.labels[idx])
        }

# 모델 및 토크나이저 로딩
model_name = "klue/bert-base"
tokenizer = BertTokenizer.from_pretrained(model_name)
model = BertForSequenceClassification.from_pretrained(model_name, num_labels=8)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

# Dataset 생성
train_dataset = LegalDataset(train_texts, train_labels, tokenizer)
val_dataset = LegalDataset(val_texts, val_labels, tokenizer)

# 평가 지표 함수
accuracy_metric = load_metric("accuracy")
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    acc = accuracy_metric.compute(predictions=preds, references=labels)
    return {"eval_accuracy": acc["accuracy"]}

class CustomSaveAndEarlyStop(TrainerCallback):
    def __init__(self, patience=5, start_epoch=20, save_dir="./best_model"):
        self.patience = patience
        self.start_epoch = start_epoch
        self.save_dir = save_dir
        self.last_loss = None
        self.epochs_no_improve = 0
        self._start_message_printed = False

        if not os.path.exists(self.save_dir):
            os.makedirs(self.save_dir)

    def on_evaluate(self, args, state, control, metrics=None, **kwargs):
        if metrics is None or "eval_loss" not in metrics:
            return control

        epoch = int(state.epoch)
        current_loss = metrics["eval_loss"]

        # start_epoch 이전은 메시지 1회만 출력
        if epoch < self.start_epoch:
            if not self._start_message_printed:
                print(f"{epoch} epoch 이전은 저장 조건 대상이 아닙니다. (start_epoch = {self.start_epoch}) 이후부터 평가 시작")
                self._start_message_printed = True
            self.last_loss = current_loss
            return control

        # 직전 loss와 비교
        if self.last_loss is None or current_loss < self.last_loss:
            print(f"{epoch}에서 val_loss 개선됨 → 모델 저장")
            self.epochs_no_improve = 0
            self.last_loss = current_loss
            kwargs['model'].save_pretrained(self.save_dir)
            kwargs['model'].config.save_pretrained(self.save_dir)
        else:
            self.epochs_no_improve += 1
            print(f"{epoch}에서 val_loss 개선되지 않음 ({self.epochs_no_improve}/{self.patience})")
            self.last_loss = current_loss  # 중요!
            if self.epochs_no_improve >= self.patience:
                print("조기 종료 발생")
                control.should_training_stop = True

        return control

# 학습 설정 (자동 저장 OFF)
training_args = TrainingArguments(
    output_dir='./klue_bert_results',
    num_train_epochs=40,
    per_device_train_batch_size=4,
    per_device_eval_batch_size=4,
    logging_steps=5,
    eval_strategy="epoch",
    save_strategy="no",  # 자동 저장 하지 않음
    load_best_model_at_end=False,
    report_to="none"
)

# Trainer 생성
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    compute_metrics=compute_metrics,
    callbacks=[CustomSaveAndEarlyStop(patience=5, start_epoch=20)]
)

# 모델 학습
trainer.train()

# 저장된 best 모델 로드
best_model_path = "./best_model"
best_model = BertForSequenceClassification.from_pretrained(best_model_path).to(device)

# 평가: 혼동 행렬 & 리포트
best_model.eval()
all_preds, all_labels = [], []
for batch in val_dataset:
    inputs = {
        'input_ids': batch['input_ids'].unsqueeze(0).to(device),
        'attention_mask': batch['attention_mask'].unsqueeze(0).to(device)
    }
    with torch.no_grad():
        outputs = best_model(**inputs)
    pred = torch.argmax(outputs.logits, dim=1).item()
    all_preds.append(pred)
    all_labels.append(batch['labels'].item())

print("\n[Confusion Matrix]")
print(confusion_matrix(all_labels, all_preds))

print("\n[Classification Report]")
print(classification_report(
    all_labels,
    all_preds,
    labels=list(label_map.keys()),
    target_names=[label_map[i] for i in range(len(label_map))]
))

# 모델 저장
best_model.save_pretrained("./saved_klue_bert")
tokenizer.save_pretrained("./saved_klue_bert")

# 추론 함수
def classify_legal_issue(text):
    best_model.eval()
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=64)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        outputs = best_model(**inputs)
    pred = torch.argmax(outputs.logits, dim=1).item()
    return label_map[pred]

# 예시
example = "앱을 설치했더니 동의 없이 위치정보를 수집했어요"
print(f"\n입력: {example}\n예측된 유형: {classify_legal_issue(example)}")
