<a name=""></a>
## 0.1.1 (2016-04-12)


#### Features

*   Add main crate to Makefile ([10a24789](https://github.com/libOctavo/octavo/commit/10a24789b2f4bb78f82c9b4e9c8c752820a6d559))
*   TravisCI should use Makefile to test crates ([7d05296c](https://github.com/libOctavo/octavo/commit/7d05296c54b49eaad76ee8b0bc112114655c5a4c))
*   Create Makefile to execute tasks on each crate ([32f098b6](https://github.com/libOctavo/octavo/commit/32f098b66eafb6fc3855aa10b874e56186bd193a))
*   Extract modules into independent crates ([b9ec1a47](https://github.com/libOctavo/octavo/commit/b9ec1a47445d1dd7cba3a79c3bbe1c94015df419))
*   use `debug_assert` instead of `assert_eq` ([50066e0e](https://github.com/libOctavo/octavo/commit/50066e0e4d58295e6a44a0375c226bac24edc169))
*   Add `no-std` flag to byteorder ([8dd0143e](https://github.com/libOctavo/octavo/commit/8dd0143e2e0db663a857c803f641edc085dbb125))
*   Add profiling options for benchmarks ([74de1d97](https://github.com/libOctavo/octavo/commit/74de1d97e0faa4be81f2d10423c36c6d5afb0c0e))
*   Add Redox support ([c442e7a9](https://github.com/libOctavo/octavo/commit/c442e7a93352ece3af7c855f16c7b272bf7eea54))
*   Use only byteorder::ByteOrder to allow usage without libstd ([f6d53b30](https://github.com/libOctavo/octavo/commit/f6d53b304ccf55bd3dde512ae343d5304d5e64f4))
*   Add projectionist configuration ([e75fc701](https://github.com/libOctavo/octavo/commit/e75fc70141c90665be2552c36795364a733af568))
*   Add Clippy lints ([34da1d01](https://github.com/libOctavo/octavo/commit/34da1d011a51248ad7c4e73e65dcba5a908772a7))
* **.clog.toml:**  Add clog configuration ([bd5a603f](https://github.com/libOctavo/octavo/commit/bd5a603ff6f791dbc145730e4f74c206624582c9))
* **.travis.yml:**  GetBadges integration ([39bbb4b7](https://github.com/libOctavo/octavo/commit/39bbb4b7d28a1a3fc9435b301edb855820d42127))
* **README:**
  *  add License badge ([f52b9bdf](https://github.com/libOctavo/octavo/commit/f52b9bdf55269d3109e7862a8d4deba61d08e7ae))
  *  Add more shields ([f629fe55](https://github.com/libOctavo/octavo/commit/f629fe5572dbeed3f8ce67f5bef031dfaa82e73f))
* **benches/digest:**  Use block size in benches ([cff8835e](https://github.com/libOctavo/octavo/commit/cff8835e2eaaa2d94342b258d6c423315ed24e86))
* **bin:**  Remove tools ([7023679b](https://github.com/libOctavo/octavo/commit/7023679b5a0c385944f6b13e9ec11cbd839481e6))
* **digest:**
  *  Use typenum in Digest ([93b0d72f](https://github.com/libOctavo/octavo/commit/93b0d72fec3053c64f79302a1030a7c557afd6fb))
  *  Implement `Clone` trait ([35e0f07e](https://github.com/libOctavo/octavo/commit/35e0f07e33bae25b775e55aad9a844ceed336396), closes [#57](https://github.com/libOctavo/octavo/issues/57))
  *  Add SHA-512/224 and SHA-512/256 hash functions ([9932a497](https://github.com/libOctavo/octavo/commit/9932a497dde12b993cc59f8e56f90f031066a74b))
  *  Add quickchecks against OpenSSL ([8f970ce9](https://github.com/libOctavo/octavo/commit/8f970ce9db1cccec786d5ecdaa508a0f6394468a))
* **digest::blake2:**  Add Blake2 digest function ([c1594432](https://github.com/libOctavo/octavo/commit/c15944325117b4a0006e5d823b21ef41df84c4db))
* **digest::sha3:**  Remove std::io dependency ([7eadab57](https://github.com/libOctavo/octavo/commit/7eadab578f1833a1b141782aad141c5faa05d048))
* **digest::tiger:**
  *  finish implementation and add tests ([9b33bea3](https://github.com/libOctavo/octavo/commit/9b33bea37dd25e56c326052efdf83ef8d103eb5b))
  *  initial commit ([f0b29a85](https://github.com/libOctavo/octavo/commit/f0b29a8574e9f2a5c6d6b0971f137c19613d8154))
* **digest::tiger::Tiger2:**  Add implementation ([329e3f2c](https://github.com/libOctavo/octavo/commit/329e3f2c26c0811f85dac007cf014ce6f1d42893))
* **examples/sums:**  add Tiger hash ([c61d1392](https://github.com/libOctavo/octavo/commit/c61d13929e6915d3f2b018953101b973079016d0))
* **kdf::bcrypt:**  Move `bcrypt` to kdf module ([9cb4747e](https://github.com/libOctavo/octavo/commit/9cb4747e5765d50dc68a03b787655da258b36648))
* **mac::hmac:**
  *  Use GenericArray in Hmac ([3a5e7d26](https://github.com/libOctavo/octavo/commit/3a5e7d263d26c0e9c4d7303470684fa40e5f85ae))
  *  Add more tests ([89079951](https://github.com/libOctavo/octavo/commit/89079951e04ad03ebd505017beb3c096cf4018c4))
* **sum:**  add Tiger supported hashes ([ded917cb](https://github.com/libOctavo/octavo/commit/ded917cb60471a4051832a363054cdc60d0e44ad))
* **utils::buffer:**  Make buffers generic over size ([07c87c0d](https://github.com/libOctavo/octavo/commit/07c87c0d11b31760c9f2f1b56fd4c964076d70a2))
* **utils::buffer::StandardPadding:**  allow custom pads ([52e5201f](https://github.com/libOctavo/octavo/commit/52e5201f0e0e169e1430ec133e329d6ea5bd6d2c))

#### Bug Fixes

*   Test script ([339c0575](https://github.com/libOctavo/octavo/commit/339c05755a812a49121ded2937d526b0f8eb2071))
*   Add empty unstable feature to all ([ac8b6e71](https://github.com/libOctavo/octavo/commit/ac8b6e71b2e96394949da4c8d2d688b7e1ee9e96))
*   TravisCI build script ([416481a6](https://github.com/libOctavo/octavo/commit/416481a65b23d6344355c0d51f4e206e2d851a22))
*   disallow failures on nightly ([94f29db5](https://github.com/libOctavo/octavo/commit/94f29db5dde460f4d22813847b03f23f7b94ccef))
*   loosen dependencies a little and allow failures on nightly ([d8aa832a](https://github.com/libOctavo/octavo/commit/d8aa832a5634ebff3f354def847a45ea53177b9a))
*   rename `bin/` to `tools/` ([9df2b1c3](https://github.com/libOctavo/octavo/commit/9df2b1c3d3c6abe74cd49ce63e3b5812e065a890))
*   Add Cargo feature `no-std` ([d8761f49](https://github.com/libOctavo/octavo/commit/d8761f49084415c51b504a9113a8139d259c98f0))
*   Update Clippy ([81997bf7](https://github.com/libOctavo/octavo/commit/81997bf7d95589ef459aed89e6d773b6d8095dfb))
*   Fix SHA2-512/224 build ([e87d691f](https://github.com/libOctavo/octavo/commit/e87d691fc4190086199c4de018208f8177a7045e))
*   Fix SHA-224 implementation ([6c402ca1](https://github.com/libOctavo/octavo/commit/6c402ca11c7b0bfdba77b298390ccccf69bdf487))
*   Remove old lint ([3d49ddd9](https://github.com/libOctavo/octavo/commit/3d49ddd944ef6c9b37a5a223aad1487c2893e113))
*   typos in benches ([2cda3553](https://github.com/libOctavo/octavo/commit/2cda35531cbd6e2bc722f544ee031969ade26f10))
*   travis-cargo already skip benches when impossible ([3efdc9c4](https://github.com/libOctavo/octavo/commit/3efdc9c4a942e8eedefd3c26e707fb40ca46e252))
*   Test names ([fb490b46](https://github.com/libOctavo/octavo/commit/fb490b469caab51c14455e3c8fadd6d32ed768dc))
*   cleanup unneded parens ([2b3f906f](https://github.com/libOctavo/octavo/commit/2b3f906ffda31c836f966a175ed079846f9008f5))
*   follow Rust naming convention ([6fbce255](https://github.com/libOctavo/octavo/commit/6fbce2559bb4e94ccbc148a96c4c2a888ac00f3f))
*   use different type params for bcrypt salt and input ([06dc12f5](https://github.com/libOctavo/octavo/commit/06dc12f52d7377731f214a00bfbd4e61e3e9a88a))
*   follow Rust naming convention ([fee98257](https://github.com/libOctavo/octavo/commit/fee9825776e364a349a874cfce5f2ae2bfaa9028))
*   links in README ([70f05d4a](https://github.com/libOctavo/octavo/commit/70f05d4ab586d8fb2cabac0fa52a1e4099ee5836))
* **.travis.yml:**  Use standard `cargo` instead of `travis-cargo` ([da498d25](https://github.com/libOctavo/octavo/commit/da498d25731d09f279e83b050297af8c6ca22520))
* **README:**
  *  Centerize logo ([cb58b104](https://github.com/libOctavo/octavo/commit/cb58b1044a9ec62afd685d13cc9561894f3eff17))
  *  Centerize logo ([cbb91631](https://github.com/libOctavo/octavo/commit/cbb91631d18f9c822a6b176ac6806f09dab2783c))
  *  link typos ([4977bc31](https://github.com/libOctavo/octavo/commit/4977bc31bae15c4ea2fa1c21369cbc3c986fad5c))
* **bin/sum:**  fix typo ([f11af49e](https://github.com/libOctavo/octavo/commit/f11af49e4d2720396f975c8a8f30c9ee485948fa))
* **crypto::stream:**  publicize Stream{Encrypt,Decrypt} ([5bd3ec74](https://github.com/libOctavo/octavo/commit/5bd3ec7430d2e77b5124844146c249452037145e))
* **crypto::stream::chacha20:**  Fix buffer utilisation ([3e0b9b82](https://github.com/libOctavo/octavo/commit/3e0b9b827dd16f1a0f63cf5979d22e4e989a274c), closes [#34](https://github.com/libOctavo/octavo/issues/34))
* **digest:**  Use `copy_nonoverlapping` instead loops ([148b3156](https://github.com/libOctavo/octavo/commit/148b3156148d614f49eb7c6bf419a19267431257))
* **digest::sha2:**  Fix SHA-512 implementation ([c828d9cd](https://github.com/libOctavo/octavo/commit/c828d9cdb92991cb8f988ae6490a6cf5b9883145))
* **utils::buffer:**  Performance issues ([5f14349a](https://github.com/libOctavo/octavo/commit/5f14349ab56f5c678151020b45a4557b27f3a4d0))

#### Performance

* **bin/sum:**  Speed up bin/sum a little ([64badd33](https://github.com/libOctavo/octavo/commit/64badd33cf14a4095c7a7d3d09a56509031fd1f3))



<a name=""></a>
## 0.1.0 (2016-04-12)


#### Bug Fixes

*   fix typos ([ab0713ab](https://github.com/libOctavo/octavo/commit/ab0713ab2e2c395fbc0cdd62e7594ad083468bde))
*   Fix PGP key link in README ([177e644d](https://github.com/libOctavo/octavo/commit/177e644d7ab9c7f2ca3159d77e578c48e1862216))
*   more typos ([db62aec2](https://github.com/libOctavo/octavo/commit/db62aec2d85eefa49c61b1800c5c8ecf761d7f78))
*   fix typos ([ea67f8e7](https://github.com/libOctavo/octavo/commit/ea67f8e7a932500d98e9b23d1d44bf556e5be706))
*   Remove Clippy linters ([d61e61a5](https://github.com/libOctavo/octavo/commit/d61e61a50602dc91d5f6025504a266c782fe6691))
*   copy pasta error ([cd3037db](https://github.com/libOctavo/octavo/commit/cd3037dbeeef456cf41877b64c796082762e92c2))
* **crypto::stream::chacha20:**
  *  Cast buffer in read-only matter ([af8d20f4](https://github.com/libOctavo/octavo/commit/af8d20f499b892f2c749712741ed92b8ad511668))
  *  Fix unsafe code to provide valid size for slice ([ade5b292](https://github.com/libOctavo/octavo/commit/ade5b292aec6b9330692f092ea28a8f908dcfbb5))
  *  Fix wrong test case ([dd78633f](https://github.com/libOctavo/octavo/commit/dd78633fa9102c2338c1a30b7b7f803bbeb813fb))
* **utils::buffer:**  Remove unsafe call ([ce71c57b](https://github.com/libOctavo/octavo/commit/ce71c57bd6bcb65c8c07b4345a7df20b58cfae75))

#### Features

* **chacha20:**  Finish implementation ([4ad38899](https://github.com/libOctavo/octavo/commit/4ad38899c0589098ac0aa47d0eaff0a3984eabcc))
* **crypto::block:**  Move encryption traits ([43af74ff](https://github.com/libOctavo/octavo/commit/43af74ff640ce4d7cf9ed7106d8a799155799d65))
* **digest::Digest:**  Remove Digest::hex_result ([4bc3d165](https://github.com/libOctavo/octavo/commit/4bc3d165c142109c69e4f6f49f64e297ce0429b8))
* **sum:**  Add `sum` tool ([0b475b52](https://github.com/libOctavo/octavo/commit/0b475b5296c8deceda613f7cf090e0c6637d0725))



