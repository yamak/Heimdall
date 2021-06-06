/***************************************************************************
 *
 *   FileName: %{Cpp:License:FileName}
 *   Author: yusuf yamak
 *   Created On: 22.05.2021
 *   Desription:
 *
 ***************************************************************************/
#include <iostream>
#include <elfhasher.h>
using namespace std;

int main()
{
    ElfHasher elfHasher("./");

    //Append Executable directories
    elfHasher.appendExecutableDirectory("/tftpboot/RootFs/bin");
    elfHasher.appendExecutableDirectory("/tftpboot/RootFs/usr/bin");
    elfHasher.appendExecutableDirectory("/tftpboot/RootFs/usr/sbin");
    elfHasher.appendExecutableDirectory("/tftpboot/RootFs/home/root");
    elfHasher.appendExecutableDirectory("/tftpboot/RootFs/sbin");

    //Append shared object directories
    elfHasher.appendSharedObjectDirectory("/tftpboot/RootFs/lib");
    elfHasher.appendSharedObjectDirectory("/tftpboot/RootFs/lib/security");
    elfHasher.appendSharedObjectDirectory("/tftpboot/RootFs/usr/lib");

    elfHasher.start();

    return 0;
}
