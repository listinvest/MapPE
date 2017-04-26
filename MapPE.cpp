#include <windows.h>
#include <fstream>
#include <stdio.h>
#include <iostream>

using namespace std;


void PrintInfo(char *);
void Dump(char *);
void Banner();

int main(int argc, char const *argv[])
{

	if(argc<2){
		Banner();
		cout << "Usage: \n\tMapPE.exe  test.exe\n";
		exit(1);
	}

	Banner();

	fstream File;
	File.open (argv[1], std::fstream::in | std::fstream::out | std::fstream::binary);
	if(File.is_open()){


		File.seekg(0, File.end);
		int FileSize = File.tellg();
		File.seekg(0, File.beg);

		//char * PE = (char*)VirtualAlloc(NULL,sizeof(FileSize),MEM_COMMIT,PAGE_READWRITE);

		char * PE = new char[FileSize];
		
		for(int i = 0; i < FileSize; i++){
			File.get(PE[i]);
		}

		PrintInfo(PE);
		Dump(PE);
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


	DOSHeader = PIMAGE_DOS_HEADER(PE); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(PE) + DOSHeader->e_lfanew); // Initialize	
	FileHeader = &NtHeader->FileHeader;
	OptHeader = &NtHeader->OptionalHeader;


	if(PE[0] == 'M' && PE[1] == 'Z'){
		cout << "[+] \"MZ\" magic number found !\n";
		if(NtHeader->Signature == IMAGE_NT_SIGNATURE){
			cout << "[+] Valid \"PE\" signature \n\n";

			cout << "[-------------------------------------]\n";

			printf("[*] ImageBase: 0x%x\n", OptHeader->ImageBase);
			printf("[*] Address Of Entry: 0x%x\n", (OptHeader->ImageBase+OptHeader->AddressOfEntryPoint));

			cout << "[*] Number Of Sections: " << FileHeader->NumberOfSections << endl;
			cout << "[*] Number Of Symbols: " << FileHeader->NumberOfSymbols << endl;

			cout << "[*] Size Of Image: " << OptHeader->SizeOfImage << " bytes\n";
			cout << "[*] Size Of Headers: " << OptHeader->SizeOfHeaders << " bytes\n";

			printf("[*] Checksum: 0x%x\n", OptHeader->CheckSum);


			ExportTable = &OptHeader->DataDirectory[0];
			ImportTable = &OptHeader->DataDirectory[1];
			ImportAddressTable = &OptHeader->DataDirectory[12];


			printf("[*] Export Table: 0x%x\n", (ExportTable->VirtualAddress+OptHeader->ImageBase));
			printf("[*] Import Table: 0x%x\n", (ImportTable->VirtualAddress+OptHeader->ImageBase));
			printf("[*] Import Address Table: 0x%x\n", (ImportAddressTable->VirtualAddress+OptHeader->ImageBase));


			cout << "[-------------------------------------]\n\n\n";


			for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++){
				SectionHeader = PIMAGE_SECTION_HEADER(DWORD(PE) + DOSHeader->e_lfanew + 248 + (i * 40));
				cout << "##########################################\n";
				cout << "#                                        #\n";
				cout << "#   ";
				for(int c = 0; c < 8; c++){
					if(SectionHeader->Name[c] == NULL){
						cout << " ";
					}
					else{
						cout << SectionHeader->Name[c];
					}
				}
				cout << " -> ";
				printf("0x%x", (SectionHeader->VirtualAddress+OptHeader->ImageBase)); 
				cout << "                 #\n";
				
				for(int j = 0; j < (SectionHeader->SizeOfRawData/(OptHeader->SizeOfImage/20)); j++){
					cout << "#                                        #\n";
				}
			}

			cout << "##########################################\n\n";
		}
		else{
			cout << "[-] PE signature missing ! \n";
			cout << "[-] File is not a valid PE :( \n";
			exit(1);
		}	
	}
	else{
		cout << "[-] Magic number not valid !\n";
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
	FileHeader = &NtHeader->FileHeader;
	OptHeader = &NtHeader->OptionalHeader;



	DWORD ImageBase = OptHeader->ImageBase;
	
	fstream File;
	File.open ("Image.dmp", std::fstream::in | std::fstream::out | std::fstream::app | std::fstream::binary);
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
			ImageBase += SectionHeader->SizeOfRawData;
		}

		cout << "\n[+] File mapping completed !\n";
		File.close();

		cout << "[+] Mapped image dumped into Image.dmp\n";

	}
	else{
		cout << "[-] Can't create dump file !";
		exit(1);
	}
}


void Banner(){

cout << "                     _____________________\n";
cout << "  _____ _____  ______\\______   \\_   _____/\n";
cout << " /     \\__  \\ \\____ \\|     ___/|    __)_ \n";
cout << "|  Y Y  \\/ __ \\|  |_> >    |    |        \\\n";
cout << "|__|_|  (____  /   __/|____|   /_______  /\n";
cout << "      \\/     \\/|__|                    \\/ \n";

cout << "\nAuthor: Ege Balci\n";
cout << "Github: github.com/egebalci/mappe\n\n";

}