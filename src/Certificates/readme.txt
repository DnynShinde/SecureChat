To compile and run the program : 


1. Open terminal in the folder where the program is saved.
2. For program compilation:  g++ -o securechat secure_chat_app.cpp -lssl -lcrypto
3. Open new terminal for server:  ./securechat -s 
4. Open new terminal for client :  ./securechat -c 127.0.0.1


NOTE: [s for server] ,[c client] and we need to specify the ip address of the server so that client can connect to the server.
Here the -lssl is used for Openssl and -lcrypto is used for the crypto library. We used these two in the command to compile the program so that the program links these libraries to the c++ program.


ALL THE FILES REQUIRED IS PRESENT IN THE SAME FOLDER.


SYSTEM SPECIFICATION ON WHICH PROGRAM IS TESTED:


1. Dnyaneshwar's System info : 
Operating System : Ubuntu 22.04.3 LTS
OS Type : 64-bit
Processor: Intel®i5 8th Gen
Memory: 8GiB
Graphics Card: NVidia
Disk Space : 1.0 TB
g++ version : g++ (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
2. Sakshi’s System info : 
Operating System : Ubuntu 22.04.3 LTS
OS Type : 64-bit
Hardware Model : HP HP Z4 G4 Workstation
Memory : 32.0 GiB
Processor : Intel® Xeon(R) W-2133 CPU @ 3.60GHz × 12
Graphics : NV137
Disk Space : 1.0 TB
g++ version : g++ (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
3. Rishabh’s System info : 
Operating System : Ubuntu 22.04.3 LTS
OS Type : 64-bit
Processor: AMD®Ryzen 3
RAM: 8GiB
Disk Space : 1.0 TB