all: ../../../projects_build/UniPCemu/testremainder ../../../projects_build/UniPCemu/polldac.com ../../../projects_build/UniPCemu/testET4000protection.com

../../../projects_build/UniPCemu/testremainder: testremainder.asm
	nasm -i. -f bin testremainder.asm -w-all -l ../../../projects_build/UniPCemu/testremainder.lst -o ../../../projects_build/UniPCemu/testremainder.bin
	cp ../../../projects_build/UniPCemu/testremainder.bin ../../../projects_build/UniPCemu/ROM/BIOSROM.32.DIAGNOSTICS.BIN

../../../projects_build/UniPCemu/polldac.com: polldac.asm
	nasm polldac.asm -fbin -o ../../../projects_build/UniPCemu/polldac.com

../../../projects_build/UniPCemu/testET4000protection.com: testET4000protection.asm
	nasm testET4000protection.asm -fbin -o ../../../projects_build/UniPCemu/testET4000protection.com

