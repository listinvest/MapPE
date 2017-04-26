#include <windows.h>
#include <fstream>
#include <stdio.h>
#include <iostream>

using namespace std;

int main(int argc, char const *argv[])
{


	fstream File;
	File.open (argv[0], std::fstream::in | std::fstream::out | std::fstream::binary);
	if(File.is_open()){

		PrintInfo();
		Dump();
	}
	else{
		cout << "[-] Unable to open file (" << argv[0] << ")\n";
		return 0;	
	}


	return 0;
}

void PrintInfo(char * PE){

	IMAGE_DOS_HEADER * DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS * NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER * SectionHeader;
	_IMAGE_FILE_HEADER * FileHeader;
	IMAGE_OPTIONAL_HEADER * OptHeader;
	_IMAGE_DATA_DIRECTORY * ImportTable;
	_IMAGE_DATA_DIRECTORY * ImportAddressTable;
	_IMAGE_DATA_DIRECTORY * ExportTable;
	IMAGE_SECTION_HEADER * SectionHeader;	


	DOSHeader = PIMAGE_DOS_HEADER(PE); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(PE) + DOSHeader->e_lfanew); // Initialize	
	FileHeader = &NtHeader.FileHeader;
	OptHeader = &NtHeader.OptionalHeader;


	if(PE[0] == 'M' && PE[0] == 'Z'){
		cout << "[+] \"MZ\" magic number found !\n";
		if(NtHeader.Signature == IMAGE_NT_SIGNATURE){
			cout << "[+] Valid \"PE\" signature \n\n";

			cout << "[-------------------------------------]"

			printf("[*] ImageBase: 0x%x\n", OptHeader->ImageBase);
			printf("[*] Address Of Entry: 0x%x\n", (OptHeader->ImageBase+OptHeader->AddressOfEntryPoint));

			cout << "[*] Number Of Sections: " << FileHeader->NumberOfSections << endl;
			cout << "[*] Number Of Symbols: " << FileHeader->NumberOfSymbols << endl;

			cout << "[*] Size Of Image: " << OptHeader.SizeOfImage << " bytes\n";
			cout << "[*] Size Of Headers: " << OptHeader.SizeOfHeaders << " bytes\n";

			printf("[*] Checksum: 0x%x\n", OptHeader.Checksum)


			ExportTable = OptHeader.DataDirectory[0];
			ImportTable = OptHeader.DataDirectory[1];
			ImportAddressTable = OptHeader.DataDirectory[12];


			printf("[*] Export Table: 0x%x\n", (ExportTable.VirtualAddress+OptHeader.ImageBase))
			printf("[*] Import Table: 0x%x\n", (ImportTable.VirtualAddress+OptHeader.ImageBase))
			printf("[*] Import Address Table: 0x%x\n", (ImportAddressTable.VirtualAddress+OptHeader.ImageBase))


			cout << "[-------------------------------------]\n\n\n"


			for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++){
				SectionHeader = PIMAGE_SECTION_HEADER(DWORD(PE) + DOSHeader->e_lfanew + 248 + (i * 40));
				cout << "	##########################################\n";
				cout << "	#                                        #\n";
				cout << "	#   ." << SectionHeader.Name << " -> ";
				printf("0x%x\n", SectionHeader->VirtualAddress);
				cout << "               #\n";
				
				for(int j = 0; j < (SectionHeader->SizeOfRawData/(OptHeader->SizeOfImage/20); j++){
					cout << "	# 										 #\n";
				}
			}

			cout << "	##########################################\n";
		}
		else{
			cout << "[-] PE signature missing ! \n";
			cout << "[-] File is not a valid PE :( \n";
			exit(1);
		}	
	}
	else{
		cout << "[-] Magic number not valid !"
		cout << "[-] File is not a valid PE :(\n";
		exit(1);
	}
	

}



/*
WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
*/


void Dump(char * PE){

	IMAGE_DOS_HEADER * DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS * NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER * SectionHeader;
	_IMAGE_FILE_HEADER * FileHeader;
	IMAGE_OPTIONAL_HEADER * OptHeader;
	_IMAGE_DATA_DIRECTORY * ImportTable;
	_IMAGE_DATA_DIRECTORY * ImportAddressTable;
	_IMAGE_DATA_DIRECTORY * ExportTable;	


	DOSHeader = PIMAGE_DOS_HEADER(PE); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(PE) + DOSHeader->e_lfanew); // Initialize	
	FileHeader = &NtHeader.FileHeader;
	OptHeader = &NtHeader.OptionalHeader;



	DWORD ImageBase = OptHeader->ImageBase;
	
	fstream File;
	File.open ("MemDump", std::fstream::in | std::fstream::out | std::fstream::app | std::fstream::binary);
	if(File.is_open()){

		cout << "[>] Maping PE headers...\n";
		File.write((char*)PE, NtHeader->OptionalHeader.SizeOfHeaders);
		ImageBase += NtHeader->OptionalHeader.SizeOfHeaders;
		printf("[>] 0x%x\n", ImageBase);

		cout << "[>] Maping sections... " << endl;
		for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
		{
			SectionHeader = PIMAGE_SECTION_HEADER(DWORD(PE) + DOSHeader->e_lfanew + 248 + (i * 40));
			cout << "[>]  " << SectionHeader->Name << endl;
			printf("[>] 0x%x\n", ImageBase);
			
			while(1){
				if(SectionHeader->VirtualAddress > ImageBase){
					File << 0x00;
					ImageBase++;
				}
				else{
					break;
				}	
			}

			cout << "[>] Maping section headers..." << endl;
			printf("[>] 0x%x\n", ImageBase);

			File.write((char*)(DWORD(PE) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData);
			Needle += SectionHeader->SizeOfRawData;
		}
		File.close();

	}
	else{
		cout << "[-] Can't create dump file !";
		exit(1);
	}
}
