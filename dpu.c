#include <stdio.h>
#include <mram.h>
#include <stdlib.h>
#include "common.h"
#include <stdint.h>
#include <mram.h>
#include <perfcounter.h>
#include <defs.h>

#define CACHE_SIZE 512

__mram uint32_t buffer[BUFFER_SIZE_DPU];
__mram uint32_t crypted[BUFFER_SIZE_DPU];
__host __dma_aligned uint32_t ExpandedKey[176];

void AES128_t(uint32_t* state)
{
		AddRoundKey(state,ExpandedKey);
		for(int i=1;i<=10;++i)
		{		
			SubBytes(state,ExpandedKey+16*i);
			ShiftRows(state,ExpandedKey+16+i);
			if(i!=10){ MixColumns(state); }
			AddRoundKey(state,ExpandedKey+16*i);
		}
} 


int main()
{		
	int k=0,j=0,offset;
	int offset_buffer = j*(CACHE_SIZE*NR_TASKLETS)+me()*CACHE_SIZE;
	uint32_t cache[CACHE_SIZE];

	for(j=0;j*(CACHE_SIZE*NR_TASKLETS)+me()*CACHE_SIZE<BUFFER_SIZE_DPU;++j)
	{
		offset_buffer = j*(CACHE_SIZE*NR_TASKLETS)+me()*CACHE_SIZE;
		mram_read(buffer+offset_buffer,cache,CACHE_SIZE*sizeof(uint32_t));	
		for(offset=0; offset < CACHE_SIZE; offset+=16)
		{
				AES128_t(cache+offset);
		}
		mram_write(cache,crypted+offset_buffer,CACHE_SIZE*sizeof(uint32_t));
	}
	
    return 0;
}
