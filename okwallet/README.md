### 编译
```shell
export GOPATH=/your/go/path/directory  #设置GOPATH路径
cd $GOPATH
git clone https://github.com/okblockchainlab/dcrd.git ./github.com/decred/dcrd
cd ./github.com/decred/dcrd
./build.sh #run this script only if you first time build the project
./runbuild.sh
./runtest.sh
```

### 其它注意项
- 官方testnet水龙头：https://faucet.decred.org/
