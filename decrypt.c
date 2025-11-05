#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <openssl/evp.h>


void decryptfile(FILE * fpin,FILE* fpout,unsigned char* key, unsigned char* iv);
void ls_dir(char* intial_path);

int main()
{
        char* intial_path;
        intial_path = "/home/";
        ls_dir(intial_path);
        
        return 0;
}

void ls_dir(char* intial_path)
{
	// 암호화 시 사용한 것과 동일한 키와 IV 사용
	unsigned char key[] = "98765432101234567890123456123456"; // 32 chars long (AES-256)
    unsigned char iv[] = "1234567890123456"; // 16 chars long (AES Block size)
	
	DIR* dir;
	struct dirent *ent;
    
	if((dir=opendir(intial_path)) !=NULL)
	{
		while((ent=readdir(dir)) !=NULL)
		{
            // DT_REG (8)은 일반 파일
			if(ent->d_type == DT_REG)
			{
				int len = strlen(ent->d_name);
                // 파일 이름 길이가 최소 4자 이상인지 확인 후 .enc 검사
				const char* last_four = (len >= 4) ? &ent->d_name[len-4] : "";
                
				if(strcmp(last_four,".enc") == 0)
				{
                    // 메모리 할당: intial_path + 파일명 + NULL 문자
					char* full_path =(char*) malloc(strlen(ent->d_name)+strlen(intial_path)+1);
                    if (full_path == NULL) { perror("malloc failed"); continue; }
					strcpy(full_path,intial_path);
					strcat(full_path,ent->d_name);
                    
                    // 새 이름 할당: .enc를 제거한 길이 + NULL 문자
					char* new_name = (char*) malloc(strlen(full_path)-4+1); // -4 for ".enc"
                    if (new_name == NULL) { free(full_path); perror("malloc failed"); continue; }
					strncpy(new_name,full_path,strlen(full_path)-4);
                    new_name[strlen(full_path)-4] = '\0'; // NULL 종료
                    

					FILE* fpin = NULL;
					FILE* fpout = NULL;

					fpin=fopen(full_path,"rb");
					fpout=fopen(new_name,"wb");
                    
                    // 파일이 성공적으로 열렸는지 확인
                    if (fpin && fpout) {
					    decryptfile(fpin,fpout,key,iv);
                        
                        fclose(fpin);
					    fclose(fpout);
					
					    // 복호화 성공 시 암호화된 파일 삭제
					    remove(full_path);
                    } else {
                        // 파일 열기 실패 시 처리
                        if (fpin) fclose(fpin);
                        if (fpout) fclose(fpout);
                        fprintf(stderr, "Error opening files: %s or %s\n", full_path, new_name);
                    }
					
					free(full_path);
					free(new_name);
				}
			}

            // DT_DIR (4)은 디렉토리
			if(ent->d_type == DT_DIR)
			{
                // . (현재 디렉토리) 또는 .. (상위 디렉토리)는 건너뜀
                if(strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
                
                // 메모리 할당: intial_path + 디렉토리명 + / + NULL 문자
				char *full_path=(char*) malloc(strlen(intial_path)+strlen(ent->d_name)+2);
                if (full_path == NULL) { perror("malloc failed"); continue; }
				strcpy(full_path,intial_path);
				strcat(full_path,ent->d_name);
				strcat(full_path,"/");
				
                // 재귀 호출
                printf("Entering Directory: %s\n",full_path);
                ls_dir(full_path);
				
				free(full_path);
			}
		}
        closedir(dir); // 디렉토리 닫기
	} else {
        perror("Error opening directory");
    }
}


// OpenSSL 1.1.0+ 버전용: EVP_CIPHER_CTX를 동적으로 할당
void decryptfile(FILE * fpin,FILE* fpout,unsigned char* key, unsigned char* iv)
{
	//Using openssl EVP to decrypt a file
	
	const unsigned bufsize = 4096;
	unsigned char* read_buf = malloc(bufsize);
    if (!read_buf) { perror("malloc failed"); return; }
	unsigned char* cipher_buf;
	int update_len, final_len;

    // OpenSSL 1.1.0+: EVP_CIPHER_CTX를 동적으로 할당
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        free(read_buf);
        return;
    }

	// EVP_CipherInit_ex() 사용. 마지막 인자 'enc'는 0(복호화)
	if(1 != EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, 0)) {
        fprintf(stderr, "EVP_CipherInit_ex (decrypt) failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(read_buf);
        return;
    }
    
    // OpenSSL 1.1.0+: EVP_CIPHER_block_size() 사용
    const int blocksize = EVP_CIPHER_block_size(EVP_aes_256_cbc()); 
    
    // 복호화 출력 버퍼는 입력 크기 + 블록 크기만큼 필요 (안전하게)
	cipher_buf = malloc(bufsize + blocksize);
    if (!cipher_buf) { 
        perror("malloc failed"); 
        EVP_CIPHER_CTX_free(ctx); 
        free(read_buf); 
        return; 
    }

	// read file and write decrypted file until eof
	while(1)
	{
		int bytes_read = fread(read_buf,sizeof(unsigned char),bufsize,fpin);
        
        if (ferror(fpin)) { 
            perror("Error reading file"); 
            break; 
        }

        if (bytes_read > 0) {
		    if (1 != EVP_CipherUpdate(ctx, cipher_buf, &update_len, read_buf, bytes_read)) {
                fprintf(stderr, "EVP_CipherUpdate failed\n");
                break;
            }
		    fwrite(cipher_buf,sizeof(unsigned char),update_len,fpout);
        }
        
		if(bytes_read < bufsize)
		{
			break;//EOF
		}
	}
    
    // 마지막 블록 및 패딩 제거 처리
	if (1 != EVP_CipherFinal_ex(ctx, cipher_buf, &final_len)) {
        // 복호화 시 패딩 오류가 발생하면 이 부분이 실패할 수 있습니다.
        fprintf(stderr, "EVP_CipherFinal_ex (decrypt) failed - possibly bad key or padding error.\n");
    } else {
        fwrite(cipher_buf,sizeof(unsigned char),final_len,fpout);
    }

    // OpenSSL 1.1.0+: EVP_CIPHER_CTX_free() 사용
	EVP_CIPHER_CTX_free(ctx); 

	free(cipher_buf);
	free(read_buf);
}