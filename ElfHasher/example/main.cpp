/* Copyright 2021 Yusuf YAMAK. All Rights Reserved.
   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
*/
#include <iostream>
#include <elfhasher.h>
using namespace std;

int main()
{
    ElfHasher elfHasher("./");

    //Append Executable directories
    elfHasher.appendExecutableDirectory("/tftpboot/RootFs_Heimdall/bin");
    elfHasher.appendExecutableDirectory("/tftpboot/RootFs_Heimdall/usr/bin");
    elfHasher.appendExecutableDirectory("/tftpboot/RootFs_Heimdall/usr/sbin");
    elfHasher.appendExecutableDirectory("/tftpboot/RootFs_Heimdall/sbin");

    //Append shared object directories
    elfHasher.appendSharedObjectDirectory("/tftpboot/RootFs_Heimdall/lib");
    elfHasher.appendSharedObjectDirectory("/tftpboot/RootFs_Heimdall/lib/security");
    elfHasher.appendSharedObjectDirectory("/tftpboot/RootFs_Heimdall/usr/lib");

    elfHasher.start();

    return 0;
}
