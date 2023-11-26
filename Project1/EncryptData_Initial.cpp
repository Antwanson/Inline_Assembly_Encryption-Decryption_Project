// EncryptData.cpp
//
// This file uses the input data and key information to encrypt the input data
//

#include "Main.h"

// YOU WILL DELETE ALL THIS CODE WHEN YOU DO YOUR PROJECT - THIS IS GIVING YOU EXAMPLES OF HOW TO 
// ACCESS gPasswordHash AND gKey

void encryptData_01(char *data, int datalength)
{
	
	__asm
	{
		xor ecx, ecx //clearing the ECX and EAX registers
		xor eax, eax
		xor ebx, ebx
		mov edi, data //getting the actual data
		/***************************************************************************************************************************
		* M1 Section - commented out to make checking M2 easier */
		
		lea	esi, gPasswordHash //getting starting index
		mov ah, byte ptr[esi]
		mov al, byte ptr[esi+1]
		lea esi, gkey //getting gkey
		
		
		

		CHECK_NEXT :
		mov bh, 0
		cmp ecx, datalength //seeing if we are at the end of the data
		je DONE
		mov bl, byte ptr[edi + ecx] //moves X value into bl
		mov bh, byte ptr[esi+eax] //moves gkey into bh
		xor bl, bh 
		mov byte ptr[edi + ecx], bl //writes xor-ed value back into where we got it from
		inc ecx //counter increment
		jmp CHECK_NEXT

			DONE :

		/**************************************************************************************************************************/
	}

	return;
} // encryptData_01
void encryptData_02(char* data, int datalength)
{
	__asm
	{
		xor ecx, ecx //clearing the ECX and EAX registers
		xor eax, eax
		xor ebx, ebx
		mov edi, data //getting the actual data
		/***************************************************************************************************************************
		* M1 Section - commented out to make checking M2 easier */

		lea	esi, gPasswordHash //getting starting index
		mov ah, byte ptr[esi]
		mov al, byte ptr[esi + 1]
		lea esi, gkey //getting gkey




			CHECK_NEXT:
		mov bh, 0
		cmp ecx, datalength //seeing if we are at the end of the data
		je DONE
		mov bl, byte ptr[edi + ecx] //moves X value into bl
		mov bh, byte ptr[esi + eax] //moves gkey into bh
		xor bl, bh
		mov byte ptr[edi + ecx], bl //writes xor-ed value back into where we got it from
		inc ecx //counter increment
		jmp CHECK_NEXT

			DONE :

		/**************************************************************************************************************************/

		//Start order BEACD 

		/**************************************************************************************************************************
		/*-----| Nibble rotate out (Encrypt) CREDIT: Anthony |-----*/

		//mov edi, data //getting the actual data again (starting from beginning) aka ABCD EFGH
		xor eax, eax
		xor ebx, ebx
		xor ecx, ecx
		clc

			NRO_CHECK_NEXT :

		cmp ecx, datalength //seeing if we are at the end of the data
		je NRO_DONE

		mov al, byte ptr[edi + ecx] //first nibble   
		and al, 0xF0
		shl al, 1
		jnc NRO_Post_First_Nibble
		add al, 16

			NRO_Post_First_Nibble: //finished first nibble rotation
		clc
		mov bl, byte ptr[edi + ecx] //second nibble
		and bl, 0x0F
		shr bl, 1
		jnc NRO_Post_Second_Nibble
		add bl, 8

		NRO_Post_Second_Nibble : //finished second nibble rotation


		//Add the nibbles together :)
		add al, bl
		mov byte ptr[edi + ecx], al

		inc ecx
		jmp NRO_CHECK_NEXT

			NRO_DONE :

		/**************************************************************************************************************************/

		/**************************************************************************************************************************
		/*-----| Rotate 3 bits left (Encrypt) CREDIT: Marianela & Anthony |-----*/
		xor eax, eax
		xor ecx, ecx


			R3BL_CHECK_NEXT :
		cmp ecx, datalength //sees if we are at the end of the data
		je R3BL_DONE
		xor ebx, ebx //uses bl as second counter
		mov bl, 3 //3 shifts
		mov al, byte ptr[edi + ecx] //moves byte into al

			R3BL_NextShift : //first shift
		cmp bl, 0
		je R3BL_SHIFT_COMPLETE // if all shifts are done jump to writing to memory

		shl al, 1 //shift left 1
		jnc R3BL_NOBIT // if carry flag is 1, adds 1 to al effectively rotating the bit to the other side
		inc al
			R3BL_NOBIT : // if there is not bit to carry
		dec bl
		jmp R3BL_NextShift //repeats

			R3BL_SHIFT_COMPLETE : //means the shifting is complete in this byte

		mov byte ptr[edi + ecx], al //write result to memory

		inc ecx
		jmp R3BL_CHECK_NEXT

			R3BL_DONE :

		/**************************************************************************************************************************/

		/**************************************************************************************************************************
		/*-----| Code Table Swap (Encrypt) CREDIT: Anthony |-----*/
		xor eax, eax
		xor ecx, ecx
		xor ebx, ebx

		CTS_CHECK_NEXT :

		cmp ecx, datalength //seeing if we are at the end of the data
			je CTS_DONE

			//Operations to do per byte
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		movzx eax, byte ptr[edi + ecx] //puts byte of plaintext into full register zero extended
		lea ebx, gEncodeTable //gets the decrypt swap table

		movzx eax, [ebx + eax] //swap the value

		mov byte ptr[edi + ecx], al //write back to memory
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		inc ecx
		jmp CTS_CHECK_NEXT

			CTS_DONE :

		/**************************************************************************************************************************/

		/**************************************************************************************************************************
		/*-----| Reverse Bit Order (Encrypt) CREDIT: Christina & Anthony |-----*/
		xor eax, eax
		xor ecx, ecx //using this instead of mov ecx,0 ~ Anthony
		xor ebx, ebx
		xor edx, edx

			reverse_order_loop :
		cmp ecx, datalength // check if end of data is reached
		je reverse_bits_done // if yes, jump to invert bits

		//reverse bit order (section per byte)
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		mov bl, byte ptr[edi + ecx] //load data from memory into eax //changed pointer to byte pointer & using lower register ~ Anthony
		//mov bl, al - don't actually need this part
		mov edx, 8 //changed to 8 bc 8 bits in a byte
			reverse_loop:
		ror bl, 1
		rcl al, 1
		dec edx
		cmp edx, 0
		jne reverse_loop //loop uses ecx which we are already using so we will use jne and cmp edx instead
		mov byte ptr[edi + ecx], al

		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		inc ecx //increment counter
		jmp reverse_order_loop //repeat for next element
			reverse_bits_done :
		/**************************************************************************************************************************/

		/**************************************************************************************************************************
		/*-----| Inverse Bits (Encrypt) CREDIT: Christina & Anthony |-----*/
		xor eax, eax
		xor ecx, ecx //using this instead of mov ecx,0 ~ Anthony
		xor ebx, ebx
		xor edx, edx


			invert_bits_loop :
		cmp ecx, datalength //check if end of data is reached
		je invert_bits_done
		//invert bits 0,2,4,7 (section per byte)
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		mov al, byte ptr[edi + ecx]
		xor al, 0x95
		mov byte ptr[edi + ecx], al
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		inc ecx //increment counter
		jmp invert_bits_loop //repeat for next element
			invert_bits_done :
		/**************************************************************************************************************************/
	}
	return;
}
int encryptData_03(char* data, int datalength)
{
	int enc_round = 0;
	__asm
	{
		//Start of round code
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		M3_Next_Round:
		mov eax, enc_round
		cmp eax, gNumRounds
		je M3_Enc_Completed
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		xor ecx, ecx //clearing the ECX and EAX registers
		xor eax, eax
		xor ebx, ebx
		xor edx, edx
		mov edi, data //getting the actual data

		/***************************************************************************************************************************
		*-----| M1 & M3 Section -|- CREDIT: ANTHONY |-----*/

		lea	esi, gPasswordHash //getting p hash

		//	mov ah, byte ptr[esi]	Legacy version for comparison
		//	mov al, byte ptr[esi + 1]
		mov ebx, enc_round
		nop
		mov ah, byte ptr[esi + ebx * 4] //get starting index[round]
		mov al, byte ptr[esi + 1 + ebx * 4]

		mov dh, byte ptr[esi + 2 + ebx * 4]
		mov dl, byte ptr[esi + 3 + ebx * 4]//Hop count moved into edx aka intitialized kinda

		// if hop count is 0 then set it to 0xFFFF
		cmp edx,0
		jne Hop_Not_Zero
		mov edx, 0x0000FFFF
			Hop_Not_Zero:

		lea esi, gkey //getting gkey
			CHECK_NEXT:
		mov bh, 0
		cmp ecx, datalength //seeing if we are at the end of the data
		je DONE
		//per every byte xor w/ gkey[index]
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		xor ebx,ebx
		mov bl, byte ptr[edi + ecx] //moves X value into bl
		mov bh, byte ptr[esi + eax] //moves gkey into bh

		xor bl, bh
		mov byte ptr[edi + ecx], bl //writes xor-ed value back into where we got it from
		inc ecx //counter increment
		add eax, edx //new M3 stuff (adding hop (edx) to index (eax))
		
		cmp eax, 65537 //if index (eax) ever is greater or equal than 65537 sub 65537
		jle Index_Not_Too_High
		sub eax, 65537
			Index_Not_Too_High:
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		jmp CHECK_NEXT

		DONE :

		/**************************************************************************************************************************/

		//Start order BEACD 

		/**************************************************************************************************************************
		/*-----| Nibble rotate out (Encrypt) CREDIT: Anthony |-----*/

		//mov edi, data //getting the actual data again (starting from beginning) aka ABCD EFGH
		xor eax, eax
		xor ebx, ebx
		xor ecx, ecx
		clc

			NRO_CHECK_NEXT :

		cmp ecx, datalength //seeing if we are at the end of the data
		je NRO_DONE

		mov al, byte ptr[edi + ecx] //first nibble   
		and al, 0xF0
		shl al, 1
		jnc NRO_Post_First_Nibble
		add al, 16

			NRO_Post_First_Nibble: //finished first nibble rotation
		clc
		mov bl, byte ptr[edi + ecx] //second nibble
		and bl, 0x0F
		shr bl, 1
		jnc NRO_Post_Second_Nibble
		add bl, 8

			NRO_Post_Second_Nibble : //finished second nibble rotation


		//Add the nibbles together :)
		add al, bl
		mov byte ptr[edi + ecx], al

		inc ecx
		jmp NRO_CHECK_NEXT

			NRO_DONE :

		/**************************************************************************************************************************/

		/**************************************************************************************************************************
		/*-----| Rotate 3 bits left (Encrypt) CREDIT: Marianela & Anthony |-----*/
		xor eax, eax
		xor ecx, ecx


			R3BL_CHECK_NEXT :
		cmp ecx, datalength //sees if we are at the end of the data
		je R3BL_DONE
		xor ebx, ebx //uses bl as second counter
		mov bl, 3 //3 shifts
		mov al, byte ptr[edi + ecx] //moves byte into al

			R3BL_NextShift : //first shift
		cmp bl, 0
		je R3BL_SHIFT_COMPLETE // if all shifts are done jump to writing to memory

		shl al, 1 //shift left 1
		jnc R3BL_NOBIT // if carry flag is 1, adds 1 to al effectively rotating the bit to the other side
		inc al
			R3BL_NOBIT : // if there is not bit to carry
		dec bl
		jmp R3BL_NextShift //repeats

			R3BL_SHIFT_COMPLETE : //means the shifting is complete in this byte

		mov byte ptr[edi + ecx], al //write result to memory

		inc ecx
		jmp R3BL_CHECK_NEXT

			R3BL_DONE :

		/**************************************************************************************************************************/

		/**************************************************************************************************************************
		/*-----| Code Table Swap (Encrypt) CREDIT: Anthony |-----*/
		xor eax, eax
		xor ecx, ecx
		xor ebx, ebx

			CTS_CHECK_NEXT :

		cmp ecx, datalength //seeing if we are at the end of the data
		je CTS_DONE

		//Operations to do per byte
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		movzx eax, byte ptr[edi + ecx] //puts byte of plaintext into full register zero extended
		lea ebx, gEncodeTable //gets the decrypt swap table

		movzx eax, [ebx + eax] //swap the value

		mov byte ptr[edi + ecx], al //write back to memory
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		inc ecx
		jmp CTS_CHECK_NEXT

			CTS_DONE :

		/**************************************************************************************************************************/

		/**************************************************************************************************************************
		/*-----| Reverse Bit Order (Encrypt) CREDIT: Christina & Anthony |-----*/
		xor eax, eax
		xor ecx, ecx //using this instead of mov ecx,0 ~ Anthony
		xor ebx, ebx
		xor edx, edx

			reverse_order_loop :
		cmp ecx, datalength // check if end of data is reached
		je reverse_bits_done // if yes, jump to invert bits

		//reverse bit order (section per byte)
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		mov bl, byte ptr[edi + ecx] //load data from memory into eax //changed pointer to byte pointer & using lower register ~ Anthony
		//mov bl, al - don't actually need this part
		mov edx, 8 //changed to 8 bc 8 bits in a byte
			reverse_loop:
		ror bl, 1
		rcl al, 1
		dec edx
		cmp edx, 0
		jne reverse_loop //loop uses ecx which we are already using so we will use jne and cmp edx instead
		mov byte ptr[edi + ecx], al

		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		inc ecx //increment counter
		jmp reverse_order_loop //repeat for next element
			reverse_bits_done :
		/**************************************************************************************************************************/

		/**************************************************************************************************************************
		/*-----| Inverse Bits (Encrypt) CREDIT: Christina & Anthony |-----*/
		xor eax, eax
		xor ecx, ecx //using this instead of mov ecx,0 ~ Anthony
		xor ebx, ebx
		xor edx, edx


			invert_bits_loop :
		cmp ecx, datalength //check if end of data is reached
		je invert_bits_done
		//invert bits 0,2,4,7 (section per byte)
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		mov al, byte ptr[edi + ecx]
		xor al, 0x95
		mov byte ptr[edi + ecx], al
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		inc ecx //increment counter
		jmp invert_bits_loop //repeat for next element
			invert_bits_done :
		/**************************************************************************************************************************/
		mov eax, enc_round
		inc eax
		mov enc_round, eax
		jmp	M3_Next_Round
			M3_Enc_Completed://when all rounds done
	}
	return 0;
}
//////////////////////////////////////////////////////////////////////////////////////////////////
// EXAMPLE code to to show how to access global variables
int encryptData(char *data, int dataLength)
{
	int resulti = 0;

	gdebug1 = 0;				// a couple of global variables that could be used for debugging
	gdebug2 = 0;				// also can have a breakpoint in C code

	// You can not declare any local variables in C, but should use resulti to indicate any errors
	// Set up the stack frame and assign variables in assembly if you need to do so
	// access the parameters BEFORE setting up your own stack frame
	// Also, you cannot use a lot of global variables - work with registers

	__asm {
		// you will need to reference some of these global variables
		// (gptrPasswordHash or gPasswordHash), (gptrKey or gkey), gNumRounds

		// simple example that xors 2nd byte of data with 14th byte in the key file
		lea esi,gkey				// put the ADDRESS of gkey into esi
		mov esi,gptrKey;			// put the ADDRESS of gkey into esi (since *gptrKey = gkey)

		lea	esi,gPasswordHash		// put ADDRESS of gPasswordHash into esi
		mov esi,gptrPasswordHash	// put ADDRESS of gPasswordHash into esi (since unsigned char *gptrPasswordHash = gPasswordHash)

		mov al,byte ptr [esi]				// get first byte of password hash
		mov al,byte ptr [esi+4]				// get 5th byte of password hash
		mov ebx,2
		mov al,byte ptr [esi+ebx]			// get 3rd byte of password hash
		mov al,byte ptr [esi+ebx*2]			// get 5th byte of password hash

		mov ax,word ptr [esi+ebx*2]			// gets 5th and 6th bytes of password hash ( gPasswordHash[4] and gPasswordHash[5] ) into ax
		mov eax,dword ptr [esi+ebx*2]		// gets 4 bytes, as in:  unsigned int X = *( (unsigned int*) &gPasswordHash[4] );

		mov al,byte ptr [gkey+ebx]			// get's 3rd byte of gkey[] data

		mov al,byte ptr [gptrKey+ebx]		// THIS IS INCORRECT - will add the address of the gptrKey global variable (NOT the value that gptrKey holds)

		mov al,byte ptr [esi+0xd];			// access 14th byte in gkey[]: 0, 1, 2 ... d is the 14th byte
		mov edi,data				// Put ADDRESS of first data element into edi
		xor byte ptr [edi+1],al		// Exclusive-or the 2nd byte of data with the 14th element of the keyfile
									// NOTE: Keyfile[14] = 0x21, that value changes the case of a letter and flips the LSB
									// Capital "B" = 0x42 becomes lowercase "c" since 0x42 xor 0x21 = 0x63
	}

	return resulti;
} // encryptData

