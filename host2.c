#define _POSIX_C_SOURCE 199309L
#include <wmmintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include <dpu.h>
#include <time.h>
#include <dpu_log.h>
#include "AdvEncStdNI.h"
#define MODUL9 9
#ifndef DPU_EXE
#define DPU_EXE "./dpu"
#endif




#ifndef RANKITER
#define RANKITER 1
#endif

#if RANKITER < 37
#define NRRANKS  RANKITER
#else
#define NRRANKS 37
#endif

#define BUFFER_SIZE BUFFER_SIZE_DPU*64*NRRANKS

#define offsetRANK 64*NR_TASKLETS*BUFFER_SIZE
#define offsetDPU NR_TASKLETS*BUFFER_SIZE
#define offsetTasklets BUFFER_SIZE
#define mallocsize BUFFER_SIZE

static char car='A';
unsigned char* bufferHost;
unsigned char* cryptedDPU;
unsigned char* cryptedNI;

unsigned char key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  
int8_t chiave[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};  
unsigned char RC[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
unsigned char EK[176];

void AES128_t(unsigned char* state)
{
		AddRoundKey(state,EK);
		for(int i=1;i<=10;++i)
		{		
			SubBytes(state,EK+16*i);
			ShiftRows(state,EK+16+i);
			if(i!=10){ MixColumns(state); }
			AddRoundKey(state,EK+16*i);
		}
} 

static inline double my_clock(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC_RAW, &t);
  return (1.0e-9 * t.tv_nsec + t.tv_sec);
}

void initBuffer(unsigned char* b, const int size)
{
	for(int i=0;i<size;++i)
	{
		b[i] = rand()%26 + 'A';
	}
}

void keyExpand(unsigned char* wb, const unsigned char* k){
	int i=0;
	for(i=0;i<44*4;++i)
	{
		if(i<16) { wb[i]=k[i]; }
		else
		{
			if(i%16 == 0)
			{
				//MSByte #3
				wb[i] = wb[i-16] ^ sbox[wb[i-3]] ^ RC[((i/16)-1)];
				++i;
				//MSByte #2 (no RC)
				wb[i] = wb[i-4*4] ^ sbox[wb[i-1*4+1]];
				++i;
				//MSByte #1 (no RC)
				wb[i] = wb[i-4*4] ^ sbox[wb[i-1*4+1]];
				++i;
				//MSByte #0 (no RC)
				wb[i] = wb[i-4*4] ^ sbox[wb[i-7]];
			}
			else{ wb[i] = wb[i-16] ^ wb[i-4]; }
		}
	}
}

int main()
{
	srand(time(NULL));
	bufferHost = malloc(mallocsize);
	cryptedDPU = malloc(mallocsize);
	cryptedNI = malloc(mallocsize);
			initBuffer(bufferHost,BUFFER_SIZE);	//Initialize the buffer of length (BUFFER_SIZE ) with random bytes
	aes128_load_key(chiave);	//Key expansion schedule for AES_NI
	keyExpand(EK,key);	//Key expansion process ofr DPU AES128 implementation
	
	//Variables
	int numDPU=0;
	int nrTMP,GB_DPU=0,GB_HOST=0,GB_HOST_t=0,offHOST_t=0;
	int processedFileDPU=0;
	double initTime=0,endTime=0,toRanksTime=0,tmpTimer[5],fromRanksTime=0,ranksTime=0,HostTime=0,NI_time=0,t_time=0;
	struct dpu_set_t set, dpu, setRanks,rank;
	uint32_t each_dpu, each_rank,tot_DPU_buffer=0;
	int  tmp,nr_state=0,clockPerSec=0;
	int offDPU=0, offDPUCrypted=0,offHOST=0,offHOSTcrypted=0;
	uint32_t nrDPUs_perRANK[256];

    DPU_ASSERT(dpu_alloc_ranks(NRRANKS, NULL, &setRanks));	//Allocating DPUs
	DPU_ASSERT(dpu_get_nr_dpus(setRanks,&numDPU)); 
	DPU_ASSERT(dpu_load(setRanks, DPU_EXE, NULL));	//Loading DPU program
	DPU_ASSERT(dpu_broadcast_to(setRanks, "ExpandedKey", 0, EK, 176, DPU_XFER_DEFAULT)); //Broadcasting the expanded key to all DPUs
	
	int nrRANKS=0;
	DPU_RANK_FOREACH(setRanks,rank,each_rank)
	{
		nrRANKS++;
		DPU_ASSERT(dpu_get_nr_dpus(rank,&nrTMP));
		nrDPUs_perRANK[each_rank] = nrTMP;
	}
	for(int i=0;i<RANKITER;++i)
	{
		tot_DPU_buffer += nrDPUs_perRANK[i%nrRANKS];
	}
	printf("%d ranks (%d DPUs) \t BUFFER_SIZE_DPU = %d kb\n",nrRANKS,numDPU,BUFFER_SIZE_DPU/1024);

	initTime = my_clock();	//START Measuring performance
	//INIT DPU HASHING

		//printf("%d/%d\n",offDPU,BUFFER_SIZE);
		tmpTimer[3]=my_clock();
		DPU_RANK_FOREACH(setRanks,rank,each_rank)
		{	

			//dpu_sync(rank);	
			DPU_FOREACH(rank,dpu,each_dpu)
			{
				char* bufferDPU = bufferHost + offDPU;
				if(offDPU<BUFFER_SIZE)
				{
					DPU_ASSERT(dpu_prepare_xfer(dpu,bufferDPU));	//Prepare
					offDPU += BUFFER_SIZE_DPU;
				}
			} //end FOR_EACH
			DPU_ASSERT(dpu_push_xfer(rank,DPU_XFER_TO_DPU,"buffer",0,BUFFER_SIZE_DPU,DPU_XFER_DEFAULT));	//Transfer	
			DPU_ASSERT(dpu_launch(setRanks, DPU_ASYNCHRONOUS));
			
		}	 //FOR_EACH_RANK
		dpu_sync(setRanks);
		toRanksTime += my_clock() - tmpTimer[3];

		tmpTimer[5]=my_clock();
		DPU_RANK_FOREACH(setRanks,rank,each_rank)
		{
			DPU_FOREACH(rank,dpu,each_dpu)
			{
				if(offDPUCrypted<BUFFER_SIZE)
				{
					DPU_ASSERT(dpu_prepare_xfer(dpu,cryptedDPU+offDPUCrypted));
					offDPUCrypted+=BUFFER_SIZE_DPU;
				}
			}
			DPU_ASSERT(dpu_push_xfer(rank,DPU_XFER_FROM_DPU,"crypted",0,BUFFER_SIZE_DPU,DPU_XFER_ASYNC));
		}
	
	fromRanksTime +=my_clock() - tmpTimer[5];
	dpu_sync(setRanks);
	endTime = my_clock();
	//END DPU HASHING
	

	tmpTimer[0]=my_clock();

		for(int i=0;i<nrRANKS;++i) //FOREACH_RANK
		{
			for(int j=0;j<nrDPUs_perRANK[i];++j) //FOREACH
			{
				for(int p=0;p<BUFFER_SIZE_DPU;p+=16)
				{
					aes128_enc(bufferHost+offHOST,cryptedNI+offHOSTcrypted);
					offHOST+=16;
					offHOSTcrypted+=16;
				}

			}
		}
	
	NI_time=my_clock() - tmpTimer[0];
	
	int z,err =0;
	if(offDPU != offHOST) { err = 1; }
	//for(z=0;z<BUFFER_SIZE && err == 0;++z){if(cryptedDPU[z] != cryptedNI[z]){ err = 1; }}
	
	if(err==0){ printf("[\033[1;32mOK\033[0m] %d kb encrypted\n",offHOST/1024); }
	else{ printf("[\033[1;31mERROR\033[0m] Crypted buffers are NOT equals: z=%d\n",z);printf("OFF DPU: %d OFF HOST: %d\n",offDPU,offHOST); }
	
	printf("----PIM TOTAL hashing time: %.1f\n",1000.0*(endTime-initTime));
	printf("----AES_NI time on HOST CPU: %.1f ms.\n", 1000.0*(NI_time));
	printf("-----------------------------------------------------\n");

	dpu_free(setRanks);
	free(bufferHost);
    return 0;
}
