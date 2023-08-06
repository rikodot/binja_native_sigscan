<img alt="preview" src="https://github.com/rikodot/binja_native_sigscan/blob/main/preview.gif" width="800">

### Plugin now available in Binary Ninja's plugin manager
(allows to receive updates automatically)<br>
<img alt="plugin" src="https://github.com/rikodot/binja_native_sigscan/blob/main/plugin.jpg" width="800">

### Extra features:
- option to use custom wildcard when dealing with NORM signatures (credit: [@c0dycode](https://github.com/c0dycode))

### Functional improvements against [Binary Ninja python sigmaker plugin](https://github.com/apekros/binja_sigmaker):
- signature finding:
  - lighting fast
- signature creation example one:
  - instruction: `C7 44 24 34 00 00 00 00   mov     dword [rsp+0x34 {var_54}], 0x0`
  - binja python sigmaker resolves to `C7 44 24 34 00 00 ? ?` - wrong
  - ida c++ sigmaker resolves to `C7 44 24 ? ? ? ? ?` (correct)
  - to fix this, you must flip [this condition](https://github.com/apekros/binja_sigmaker/blob/master/__init__.py#L163-L169) AKA first test 4 bytes and then 1 byte
- signature creation example two:
  - instruction: `C7 44 24 30 07 00 00 00   mov     dword [rsp+0x30 {var_58}], 0x7`
  - binja python sigmaker resolves to `C7 44 24 30 ? ? ? ?` (wrong)
  - ida c++ sigmaker resolves to `C7 44 24 ? ? ? ? ?` (correct)
  - problem lays in the way of seeking and reading, specifically any calculations with `br.offset` and reading using `br.read32()` or `br.read8()` [around the same place as in the problem above](https://github.com/apekros/binja_sigmaker/blob/master/__init__.py#L156-L175); c++ equivalent functions are `br.Seek(addr)` and `br.Read32()` or `br.Read8()`, so what I have done was changing way of reading bytes at specific values to reading from absolute position in the binary using `bv->Read(dest, offset, len)`
- works with normal signatures (e.g. `49 28 15 ? ? 30`) and commonly used code signatures (e.g. `"\x49\x28\x15\x00\x00\x30", "xxx??x"`) so no matter what your use case might be, it should be ready to go

### Advantages against [IDA C++ sigmaker plugin](https://github.com/ajkhoury/SigMaker-x64):
- signature creation example one:
  - instruction: `83 7C 24 20 0F   cmp     dword [rsp+0x20 {var_68}], 0xf`
  - ida c++ sigmaker resolves to `83 7C 24 ? ?`
  - we resolve to `83 7C 24 20 0F` (better I suppose - binja api does this by default)
- signature creation example two:
  - instruction: `8B 54 24 24   mov     edx, dword [rsp+0x24]`
  - ida c++ sigmaker resolves to `8B 54 24 24`
  - we resolve to `8B 54 24 ?` (better I suppose - binja api does this by default)

### Usage
**RECOMMENDED: Download plugin directly from Binary Ninja's plugin manager in order to receive updates automatically**
- first copy compiled plugin into the plugins folder (`%appdata%\Binary Ninja\plugins\` or `~/.binaryninja/plugins/`)
- note that you can use both normal signatures (e.g. `49 28 15 ? ? 30`) and code signatures (e.g. `"\x49\x28\x15\x00\x00\x30", "xxx??x"`)
- finding signatures:
  1. right click into the main frame or use topbar navigation `Plugins->Find <type> sig` and enter the signature
  2. all hits will be written into the log bar along with their addresses, simply left click on a green highlited address to follow it
- creating signatures
  1. select a piece of code within the main frame in `Linear` or `Graph` view
  2. right click into the main frame or use topbar navigation `Plugins->Create <type> sig from range`
  3. signature is written into the log bar (on windows also copied directly to the clipboard), if you want to copy previously created signature, simply find it in the log bar, right click it and hit copy to avoid recreating it or use Ctrl+C shortcut

### Build process
1. head to the binja api link you can find in `C:\Program Files\Vector35\BinaryNinja\api_REVISION.txt` (in my case, at the time of creating this repository, it is `https://github.com/Vector35/binaryninja-api/tree/919384bb2bb9216e000750a00793549ef7a46d87`)
2. download repository as a zip (click green 'Code' button and hit 'Download ZIP')
3. put wherever you want and extract it
4. open cmd/terminal and navigate into the extracted folder
```bash
cd examples
git clone https://github.com/rikodot/binja_native_sigscan
cd binja_native_sigscan
cmake -S . -B build
```
5. launch newly generated Visual Studio .sln project located in (...\binaryninja-api\examples\binja_native_sigscan\build\) and build the project OR use `cmake --build build -j8` instead
6. to load the plugin, copy compiled binary into the plugins folder
   - on windows `copy ".\build\Release\sigscan.dll" "%appdata%\Binary Ninja\plugins\sigscan.dll"`
   - on linux `cp ./build/out/bin/libsigscan.so ~/.binaryninja/plugins/libsigscan.so`

### Known issues
- if a code signature is provided and the 'find norm signature' process is executed, Binary Ninja will freeze and crash, potentially caused by an infinite loop, similar issue may also occur in various other scenarios
- creating signature from `Hex Editor` view within the main frame most likely causes crash as partial instructions might be selected

### Backstory
I have been using IDA for majority of my reverse engineering career and recently decided to switch to Binary Ninja. I work with signatures on daily basis and this plugin is a must for me. Although there already is a community plugin for the exact same purpose, it is frankly unusable for binaries over 50KB in size as it is incredibly slow and on top of that contains two bugs causing creation of signatures with wrongly placed wild bytes resulting in signatures not being compatible with different compilations of the same binary. I still want to note that the python version was a nice resource in creation of this version.
