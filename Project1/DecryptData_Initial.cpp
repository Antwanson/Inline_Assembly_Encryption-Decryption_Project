// DecryptData.cpp
//
// THis file uses the input data and key information to decrypt the input data
//

#include "Main.h"

// YOU WILL DELETE ALL THIS CODE WHEN YOU DO YOUR PROJECT - THIS IS GIVING YOU EXAMPLES OF HOW TO 
// ACCESS gPasswordHash AND gKey

void decryptData_01(char *data, int sized)
{
	__asm
	{
		mov edi, data //getting the actual data
		//Start order BEACD in REVERSE 

		/**************************************************************************************************************************
		/*-----| Inverse Bits (Encrypt) CREDIT: Christina & Anthony |-----*/
		xor eax, eax
		xor ecx, ecx //using this instead of mov ecx,0 ~ Anthony
		xor ebx, ebx
		xor edx, edx


		invert_bits_loop :
		cmp ecx, sized //check if end of data is reached
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

		/**************************************************************************************************************************
		/*-----| Reverse Bit Order (Decrypt) CREDIT: Christina & Anthony |-----*/
		xor eax, eax
		xor ecx, ecx //using this instead of mov ecx,0 ~ Anthony
		xor ebx, ebx
		xor edx, edx

		reverse_order_loop :
		cmp ecx, sized // check if end of data is reached
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
		/*-----| Code Table Swap (Decrypt) CREDIT: Anthony |-----*/
		xor eax, eax
		xor ecx, ecx
		xor ebx, ebx

		CTS_CHECK_NEXT :

		cmp ecx, sized //seeing if we are at the end of the data
			je CTS_DONE

			//Operations to do per byte
		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			movzx eax, byte ptr[edi + ecx] //puts byte of plaintext into full register zero extended
			lea ebx, gDecodeTable //gets the encrypt swap table

			movzx eax, [ebx + eax] //swap the value

			mov byte ptr[edi + ecx], al //write back from register

		//-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			inc ecx
			jmp CTS_CHECK_NEXT

			CTS_DONE :

		/**************************************************************************************************************************/

		/**************************************************************************************************************************
		/*-----| Rotate 3 bits left (Decrypt) Credit: Marianela & Anthony |-----*/
		xor ecx, ecx
		xor eax, eax

		R3BL_CHECK_NEXT :
		cmp ecx, sized //sees if we are at the end of the data
		je R3BL_DONE
		xor ebx, ebx //uses bl as second counter
		mov bl, 3 //3 shifts
		mov al, byte ptr[edi + ecx] //moves byte into al

		R3BL_NextShift : //first shift
		cmp bl, 0
		je R3BL_SHIFT_COMPLETE // if all shifts are done jump to writing to memory

		shr al, 1 //shift left 1
		jnc R3BL_NOBIT // if carry flag is 1, adds 128 to al effectively rotating the bit to the other side
		add al, 128
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
		/*-----| Nibble rotate out (dycrypt) CREDIT: Anthony |-----*/

		//mov edi, data //getting the actual data again (starting from beginning) aka ABCD EFGH
		xor eax, eax
		xor ebx, ebx
		xor ecx, ecx
		clc

			NRO_CHECK_NEXT :

		cmp ecx, sized //seeing if we are at the end of the data
		je NRO_DONE

		mov al, byte ptr[edi + ecx] //first nibble   
		and al, 0xF0
		shr al, 5
		jnc NRO_Post_First_Nibble
		add al, 8

			NRO_Post_First_Nibble :
		shl al, 4	//finished first nibble rotation


		clc
		mov bl, byte ptr[edi + ecx] //second nibble
		and bl, 0x0F
		shl bl, 5
		jnc NRO_Post_Second_Nibble
		add bl, 16

			NRO_Post_Second_Nibble :
		shr bl, 4	//finished second nibble rotation


			//Add the nibbles together :)
		add al, bl
		mov byte ptr[edi + ecx], al

		inc ecx
		jmp NRO_CHECK_NEXT

			NRO_DONE :

		/**************************************************************************************************************************/

		xor ecx, ecx //clearing the ECX and EAX registers
		xor eax, eax
		xor ebx, ebx
		/***************************************************************************************************************************
		* M1 Section - commented out to make checking M2 easier */

		lea	esi, gPasswordHash //getting starting index
		mov ah, byte ptr[esi]
		mov al, byte ptr[esi + 1]
		lea esi, gkey //getting gkey
		



	CHECK_NEXT:
		mov bh, 0
		cmp ecx, sized //seeing if we are at the end of the data
		je DONE
		mov bl, byte ptr[edi + ecx] //moves X value into bl
		mov bh, byte ptr[esi + eax] //moves gkey into bh
		xor bl, bh
		mov byte ptr[edi + ecx], bl //writes xor-ed value back into where we got it from
		inc ecx //counter increment
		jmp CHECK_NEXT

			DONE :
		/***************************************************************************************************************************/
		
		
	}

	return;
} // decryptData_01


//////////////////////////////////////////////////////////////////////////////////////////////////
// EXAMPLE code to show how to access global variables
int decryptData(char *data, int dataLength)
{
	int resulti = 0;

	gdebug1 = 0;					// a couple of global variables that could be used for debugging
	gdebug2 = 0;					// also can have a breakpoint in C code

	// You can not declare any local variables in C, but can use resulti to indicate any errors
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

		mov al,byte ptr [esi+0]				// get first byte of password hash
		mov al,byte ptr [esi+1]				// get 5th byte of password hash
		mov ebx,2
		mov al,byte ptr [esi+ebx]			// get 3rd byte of password hash
		mov al,byte ptr [esi+ebx*2]			// get 5th byte of password hash

		mov ax,word ptr [esi+ebx*2]			// gets 5th and 6th bytes of password hash ( gPasswordHash[4] and gPasswordHash[5] ) into ax
		mov eax,dword ptr [esi+ebx*2]		// gets 4 bytes, as in:  unsigned int X = *( (unsigned int*) &gPasswordHash[4] );

		mov al,byte ptr [gkey+ebx]			// get's 3rd byte of gkey[] data

		mov al,byte ptr [gptrKey+ebx]		// THIS IS INCORRECT - will add the address of the gptrKey global variable (NOT the value that gptrKey holds)

		mov al,byte ptr [esi+0xd];			// access 14th byte in gkey[]: 0, 1, 2 ... d is the 14th byte
		mov edi,data						// Put ADDRESS of first data element into edi
		xor byte ptr [edi+1],al				// Exclusive-or the 2nd byte of data with the 14th element of the keyfile
											// NOTE: Keyfile[14] = 0x21, that value changes the case of a letter and flips the LSB
											// Lowercase "c" = 0x63 becomes capital "B" since 0x63 xor 0x21 = 0x42
	}

	return resulti;
} // decryptData

