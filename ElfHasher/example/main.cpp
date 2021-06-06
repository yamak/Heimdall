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
