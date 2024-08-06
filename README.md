# NCCoE.factory.pub
Public repository for the NCCoE Factory Use Case

>>>>Prerequisites<<<
> Obtain a VaultIC for RaspberryPi kit from SealSQ
>> Contact: sclark@sealsq.com
> Run on Bookworm 64 RaspberryPi distribution.
> Optional: Create keypair and certificates on Windows

Raspberry Pi:
> Demonstrations:
>> Create the keypair in VaultIC
>> Create CSR
>> Download the certificate from INeS using CSR
>> Provision certificate to the VaultIC
>> Read the Certificate from the VaultIC
>> Sign using the VaultIC private key

Build demonstrations:
- Browse to the /scripts folder
	o chmod +rwx *.sh
	o ./install.sh
	o ./build.sh

Create keypair & provision certificate to the VaultIC:
- Browse to the /scripts folder
	o ./factoryProvision.sh

Read the Certificate from the VaultIC:
- Browse to the /scripts folder
	o ./readCert.sh


Sign using the VaultIC private key:
- Browse to the scripts folder:
	o ./signFactory.sh


Windows:
> Demonstrations
>> Create the key pair in VaultIC
>> Create CSR
>> Download the certificate from INeS using CSR

Build the demonstration
- From Visual Studio
	o open factory.sln
	o Select Build Solution
	o run factory.exe
		> factory.exe

