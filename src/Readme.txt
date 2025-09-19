To compile and run the program for Task-1,Task-2 : 


Open terminal in the folder where the program is saved.
For program compilation:  g++ -o securechat secure_chat_app.cpp -lssl -lcrypto -lpthread
Open new terminal for server:  ./chat -s 
Open new terminal for client :  ./chat -c bob1


To compile and run the program for Task-3, : 


Open terminal in the folder where the program is saved.
For program compilation:  g++ -o securechat secure_chat_interceptor.cpp -lssl -lcrypto -lpthread
Open new terminal for attacker:  ./chat -d alice1 bob1
Open new terminal for server:  ./chat -s 
Open new terminal for client :  ./chat -c bob1
To script to poison : /poison-dns-alice1-bob1.sh
For script to unpoison :  /unpoison-dns-alice1-bob1.sh


To compile and run the program for Task-4, Task-5  :


Open terminal in the folder where the program is saved.
For program compilation:  g++ -o securechat secure_chat_active_interceptor.cpp -lssl -lcrypto -lpthread
Open new terminal for attacker:  ./chat -d alice1 bob1
Open new terminal for server:  ./chat -s 
Open new terminal for client :  ./chat -c bob1
For Task 4 script : ~/poison-dns-alice1-bob1.sh
For Task 4 script to unpoison :  
For Task 5 script to poison :  /.arp-poison-alice1-bob.sh
For Task 5 script to unpoison :  /.arp-unpoison-alice1-bob1.sh




NOTE: [s for server] ,[c client] and we need to specify the ip address of the server so that client can connect to the server.
Here the -lssl is used for Openssl and -lcrypto is used for the crypto library and -lpthread for the multithreading library . We used these two in the command to compile the program so that the program links these libraries to the c++ program.


We have maintained the subfolders for respective TASKS.
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