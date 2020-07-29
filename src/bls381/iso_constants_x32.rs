use super::super::big::NLEN;
use crate::arch::Chunk;

// ISO-3 Mapping values
pub const ISO3_XNUM: [[Chunk; NLEN]; 8] = [
    [
        0xaaa97d6, 0x11c55555, 0x1671c718, 0xc71c687, 0xe15d5c2, 0x211e285, 0x10aa22d6, 0x73fa740,
        0x532c52d, 0x123ebf6c, 0xed6dea6, 0x1d1c667d, 0x1c759507, 0x2,
    ],
    [
        0xaaa97d6, 0x11c55555, 0x1671c718, 0xc71c687, 0xe15d5c2, 0x211e285, 0x10aa22d6, 0x73fa740,
        0x532c52d, 0x123ebf6c, 0xed6dea6, 0x1d1c667d, 0x1c759507, 0x2,
    ],
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x1fffc71a, 0x154fffff, 0x3555549, 0x5555397, 0xa418147, 0x635a790, 0x11fe6882, 0x15bef5c1,
        0xf984f87, 0x16bc3e44, 0xc849bf3, 0x17553378, 0x1560bf17, 0x8,
    ],
    [
        0x1fffc71e, 0x154fffff, 0x3555549, 0x5555397, 0xa418147, 0x635a790, 0x11fe6882, 0x15bef5c1,
        0xf984f87, 0x16bc3e44, 0xc849bf3, 0x17553378, 0x1560bf17, 0x8,
    ],
    [
        0x1fffe38d, 0x1aa7ffff, 0x11aaaaa4, 0x12aaa9cb, 0x520c0a3, 0x31ad3c8, 0x18ff3441,
        0x1adf7ae0, 0x7cc27c3, 0x1b5e1f22, 0x6424df9, 0x1baa99bc, 0xab05f8b, 0x4,
    ],
    [
        0xaaa5ed1, 0x7155555, 0x19c71c62, 0x11c71a1e, 0x18575709, 0x8478a15, 0x2a88b58, 0x1cfe9d02,
        0x14cb14b4, 0x8fafdb0, 0x1b5b7a9a, 0x147199f5, 0x11d6541f, 0xb,
    ],
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
];
pub const ISO3_XDEN: [[Chunk; NLEN]; 8] = [
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x1fffaa63, 0xff7ffff, 0x14ffffee, 0x17fffd62, 0xf6241ea, 0x9507b58, 0xafd9cc3, 0x109e70a2,
        0x1764774b, 0x121a5d66, 0x12c6e9ed, 0x12ffcd34, 0x111ea3, 0xd,
    ],
    [
        0xc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x1fffaa9f, 0xff7ffff, 0x14ffffee, 0x17fffd62, 0xf6241ea, 0x9507b58, 0xafd9cc3, 0x109e70a2,
        0x1764774b, 0x121a5d66, 0x12c6e9ed, 0x12ffcd34, 0x111ea3, 0xd,
    ],
    [
        0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
];
pub const ISO3_YNUM: [[Chunk; NLEN]; 8] = [
    [
        0x11c6d706, 0x167e38e3, 0x124bda04, 0x184bd7f1, 0x1e500fc8, 0x1cec3e93, 0x126fd510,
        0x1a940fec, 0x130f7da5, 0x183b688c, 0x16693062, 0x15682276, 0x130477c7, 0xa,
    ],
    [
        0x11c6d706, 0x167e38e3, 0x124bda04, 0x184bd7f1, 0x1e500fc8, 0x1cec3e93, 0x126fd510,
        0x1a940fec, 0x130f7da5, 0x183b688c, 0x16693062, 0x15682276, 0x130477c7, 0xa,
    ],
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0xaaa97be, 0x11c55555, 0x1671c718, 0xc71c687, 0xe15d5c2, 0x211e285, 0x10aa22d6, 0x73fa740,
        0x532c52d, 0x123ebf6c, 0xed6dea6, 0x1d1c667d, 0x1c759507, 0x2,
    ],
    [
        0x1fffc71c, 0x154fffff, 0x3555549, 0x5555397, 0xa418147, 0x635a790, 0x11fe6882, 0x15bef5c1,
        0xf984f87, 0x16bc3e44, 0xc849bf3, 0x17553378, 0x1560bf17, 0x8,
    ],
    [
        0x1fffe38f, 0x1aa7ffff, 0x11aaaaa4, 0x12aaa9cb, 0x520c0a3, 0x31ad3c8, 0x18ff3441,
        0x1adf7ae0, 0x7cc27c3, 0x1b5e1f22, 0x6424df9, 0x1baa99bc, 0xab05f8b, 0x4,
    ],
    [
        0x1c718b10, 0xd9b8e38, 0x1712f678, 0x1212f4ad, 0x74524e7, 0x1be34d51, 0xa1ac3a5, 0x6f43c4c,
        0x10761b0f, 0xf1c08d6, 0x1efdc10f, 0x16d9ef37, 0x4c9ad43, 0x9,
    ],
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
];
pub const ISO3_YDEN: [[Chunk; NLEN]; 8] = [
    [
        0x1fffa8fb, 0xff7ffff, 0x14ffffee, 0x17fffd62, 0xf6241ea, 0x9507b58, 0xafd9cc3, 0x109e70a2,
        0x1764774b, 0x121a5d66, 0x12c6e9ed, 0x12ffcd34, 0x111ea3, 0xd,
    ],
    [
        0x1fffa8fb, 0xff7ffff, 0x14ffffee, 0x17fffd62, 0xf6241ea, 0x9507b58, 0xafd9cc3, 0x109e70a2,
        0x1764774b, 0x121a5d66, 0x12c6e9ed, 0x12ffcd34, 0x111ea3, 0xd,
    ],
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x1fffa9d3, 0xff7ffff, 0x14ffffee, 0x17fffd62, 0xf6241ea, 0x9507b58, 0xafd9cc3, 0x109e70a2,
        0x1764774b, 0x121a5d66, 0x12c6e9ed, 0x12ffcd34, 0x111ea3, 0xd,
    ],
    [
        0x12, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x1fffaa99, 0xff7ffff, 0x14ffffee, 0x17fffd62, 0xf6241ea, 0x9507b58, 0xafd9cc3, 0x109e70a2,
        0x1764774b, 0x121a5d66, 0x12c6e9ed, 0x12ffcd34, 0x111ea3, 0xd,
    ],
    [
        0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
    [
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
];

// ISO-11 Mapping values
pub const ISO11_XNUM: [[Chunk; NLEN]; 12] = [
    [
        0x134649b7, 0x1560b313, 0x198b5bab, 0x185abe5, 0xe2c8561, 0x1dab66da, 0x17fc989,
        0x11145ae0, 0x56b303e, 0xeccc0ac, 0xe024407, 0x1d066681, 0x1a05f2b1, 0x8,
    ],
    [
        0x13cb83bb, 0x1a7778d, 0x630d5ba, 0x11e54de6, 0x1e86b483, 0x119e3868, 0x105fd597,
        0xb65ed50, 0x1c7c17e7, 0x110a3d40, 0x1622eac, 0x1287565e, 0x1294ed3e, 0xb,
    ],
    [
        0xc9edcb0, 0xbcfced, 0x25ca7f8, 0x187c7a54, 0xe25c958, 0x1280f634, 0xf95a1e3, 0xe652b30,
        0x1bce0324, 0xe8854d0, 0x7441231, 0x12ecf1d8, 0x154005db, 0x6,
    ],
    [
        0x1d9b6861, 0xd9c4320, 0x41c64f1, 0xdc4b9c6, 0x13083533, 0x1944f8d9, 0x1c97c6cc, 0xcad51b7,
        0x12d7f5e4, 0x183f2aa0, 0x13818274, 0x1f98db6e, 0x178e7166, 0xb,
    ],
    [
        0xc8895d9, 0x8aa674d, 0x79df114, 0x1450de60, 0x1ac18985, 0x15b2cc17, 0xcfc21bb, 0xb424aff,
        0x1499db99, 0x1f208c72, 0x1990ad2c, 0x333e886, 0x99726a3, 0x7,
    ],
    [
        0xf652983, 0x89e0e33, 0x19cf4673, 0xe1a5b95, 0x8f90a08, 0x15c84bf3, 0x66e7b4e, 0xfbb2a4f,
        0x15db3cb1, 0x1fbd3a55, 0x744806, 0x1ae627fe, 0x30c3250, 0xb,
    ],
    [
        0x139ed84, 0xebf912d, 0x14bb2b7, 0x4a25182, 0x6b2a8da, 0x110c7ce4, 0x13864023, 0x4c9e1f1,
        0x1fb11586, 0x1c573295, 0x1a8dc9b0, 0x1fc89a52, 0x16ed6553, 0x6,
    ],
    [
        0x3f0c88e, 0x65ab0c7, 0x1d1d6be7, 0xf91f191, 0x753339b, 0x3177879, 0x16c69a0b, 0x1564eb69,
        0x13356de5, 0x6888bf2, 0x1a1d0e21, 0x357b7c5, 0x1b81e770, 0xb,
    ],
    [
        0x497e317, 0xb8cc354, 0xdd3a55b, 0x52be52d, 0x1d1de4fa, 0xb649462, 0x15d28b16, 0xd9cf3ea,
        0xdc43b75, 0xb1df4c8, 0x1ee42ccd, 0x134f1f88, 0xd3cf1f, 0x4,
    ],
    [
        0x1e390c9e, 0x1920833d, 0xc9de5f, 0x12165db8, 0x11b7fa31, 0xa5d7a5d, 0x12659d8c,
        0x1007418b, 0x2dd2ecb, 0xae89c79, 0xb830dd4, 0x179f4f88, 0x9b1f8e1, 0xb,
    ],
    [
        0x1605fb7b, 0x133ef9f8, 0xa177b32, 0x16ee3f18, 0x14866f69, 0x19b001d8, 0x1e5b542b,
        0x1bbccf0f, 0xdfa7dcc, 0xe92b2d8, 0x1cb63b02, 0x139c0fc4, 0x321da07, 0x8,
    ],
    [
        0xba2d229, 0xe45d174, 0x134e47ea, 0x1637016c, 0x6b68c24, 0x1f8de126, 0x1ef08f02, 0xfc45906,
        0x1d31d79d, 0x1c0f6f71, 0xf47a588, 0x1c4c1ce1, 0xe08c248, 0x3,
    ],
];
pub const ISO11_XDEN: [[Chunk; NLEN]; 11] = [
    [
        0xd21b1c, 0x9e7cfd2, 0xd0f7e26, 0x11ad037c, 0xac62b55, 0x430bfe4, 0x2ea7256, 0x9746b69,
        0xf01d5ef, 0x1a5e9fd3, 0x62cb98b, 0x19fe335c, 0xca8d548, 0x4,
    ],
    [
        0x82b3bff, 0xe413b76, 0xc09ba79, 0x155108d9, 0xbf5713d, 0x12c4624, 0x30049b, 0x19419e10,
        0x167041e8, 0x14c729b1, 0x122d1c44, 0x16ab3886, 0x561a5de, 0x9,
    ],
    [
        0x1cb83e19, 0x611cdd2, 0x53fb73f, 0x7a12cf9, 0xceacd6a, 0x700588d, 0x1347f299, 0xdeb4e31,
        0x1f6f8941, 0xdff94c8, 0x4df98a, 0xf4644bd, 0x12962fe5, 0x5,
    ],
    [
        0xdc62cd8, 0x186f449c, 0x1b3d7104, 0xdaa487d, 0x16fd0497, 0x1455e146, 0x15455332,
        0x7e2d62c, 0x145b0824, 0x1be2075a, 0x120eabfb, 0xb15c5fd, 0x1425581a, 0x1,
    ],
    [
        0x1532a21e, 0x1ce9cad9, 0xd5e0754, 0x537503e, 0x106da9bd, 0x27419d9, 0xaee35ad, 0xb34240c,
        0x1dffdfc7, 0x1a1f3d03, 0x29bc757, 0x4522950, 0x1a8e1620, 0x9,
    ],
    [
        0x1f6304a5, 0x16fcd14, 0x8a3c470, 0x1a49788, 0x982f740, 0x1e77925c, 0x1534290e, 0x1d39d395,
        0x9395735, 0x18283637, 0x154e43df, 0x9cccf72, 0x7355f8e, 0x7,
    ],
    [
        0xee84a3a, 0x12ba24b, 0x3781b3b, 0x766a71e, 0xde9cea7, 0x3983157, 0x62538b8, 0x1335ea74,
        0x1570f57, 0x1f02cb39, 0x3cf8318, 0x2d26c32, 0x172caacf, 0x3,
    ],
    [
        0x1dcc5a5e, 0xfbeccdd, 0x478b4c4, 0xb72913a, 0x2c580fa, 0x10e6fcc1, 0x2a0665b, 0x1843794d,
        0x196e7f63, 0x3a6780c, 0xc2cfd6c, 0x1ac95164, 0xa7ac2a9, 0xa,
    ],
    [
        0x19a1d641, 0x1bb761d3, 0xe90dc11, 0x4cd2557, 0x18835038, 0x6d33f9c, 0x19add040, 0x3ae2c26,
        0xce07f8d, 0xd7e3d1e, 0x17a482cf, 0x1b4a9f04, 0x10ecf6a, 0x5,
    ],
    [
        0x8ecdd0a, 0xb1c268b, 0x1e19400b, 0xe9c9696, 0x11c15931, 0x99cbc79, 0xdddb7d, 0x1dd2defa,
        0xf682b4, 0x159d2b34, 0x11db5b8f, 0x13d255a8, 0x15fc13ab, 0x4,
    ],
    [
        0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
];
pub const ISO11_YNUM: [[Chunk; NLEN]; 16] = [
    [
        0x1707bb33, 0x14c22b8c, 0xee8f0af, 0x18f5dd36, 0x143d3cd0, 0x17b64ab2, 0x548ad4a,
        0x11c9150d, 0x1a11ad13, 0xa4c06e7, 0x96747c2, 0x17449dc0, 0x10d97c81, 0x4,
    ],
    [
        0xe41c696, 0x4bf3ad1, 0xbea2ff8, 0xace232c, 0x1ad34d6c, 0x11a1f5b3, 0xf43e41, 0xd84a9e7,
        0x31223e9, 0x1bb7da34, 0x15440db5, 0x9dcb023, 0x14996a10, 0x9,
    ],
    [
        0x72de1f6, 0x6ff1206, 0xc0148ee, 0x1aa42c51, 0xda7d26, 0x1f25c8a0, 0x138b0d12, 0x1acb1463,
        0x142552e2, 0x351da4c, 0x1d28e132, 0x152cdccd, 0xcc786ba, 0x0,
    ],
    [
        0x10e5f4cb, 0x11aae3bd, 0x11877b29, 0xb5753d, 0x11cf9de4, 0x11f60192, 0x4702792,
        0x1721dd6f, 0x17d42aa7, 0x16c3a33a, 0x1e261d46, 0x11303842, 0x1f86376e, 0x0,
    ],
    [
        0x12e8fedb, 0xdb6d767, 0x4102a10, 0xff1b813, 0x11adc2ee, 0x1fe9109a, 0x2e1e60c, 0x1f7c79ca,
        0x4195536, 0x1510a94e, 0x172bd3f8, 0x1fc1fe26, 0xcc03fde, 0x4,
    ],
    [
        0x1633a5f0, 0xd91d589, 0x16a01ca6, 0x1ec64d92, 0x1544e203, 0xe1e9d6a, 0x1ef5d941,
        0x1a95f5b6, 0x74a7d0, 0xdc78535, 0x8847847, 0xc696d4, 0x603fca4, 0xb,
    ],
    [
        0x1fe9d6f2, 0xb0fc42a, 0x3d057b2, 0x10f5848c, 0x14f3747a, 0x9e26b1, 0x132d48c5, 0x19457c30,
        0x1ce75bb8, 0x13bcb59, 0xcb25df4, 0x1f583779, 0xab0b9bc, 0x2,
    ],
    [
        0x1870fb29, 0xaf26518, 0x17fa4d68, 0xc8aa1fd, 0x842642f, 0x6d36136, 0x7ff40e, 0x17fc77bb,
        0x14170a05, 0x9653633, 0x17a649af, 0x67570df, 0x187c8d53, 0x4,
    ],
    [
        0x1bdba587, 0x1b872bb, 0x181e8d8, 0xca4038f, 0xcabe69d, 0x17350f90, 0x9b07a2d, 0x2ccf3b8,
        0x1b8f3abd, 0x10f26d0d, 0x1a232788, 0x1b2cd097, 0x1fc4018b, 0x4,
    ],
    [
        0xa731c30, 0x1d7d575e, 0x13ae9bca, 0x1ee0abba, 0xd43b9b3, 0xf3f68f2, 0x1bf81a61,
        0x14f22b5e, 0x3c42a0c, 0x1d6d0a51, 0x88eaf79, 0x30d7b6a, 0x1bba7a1, 0x7,
    ],
    [
        0x1011c132, 0x9b88d6, 0xfeebf3a, 0x1e74b99c, 0x1e61031b, 0x1f20b1c4, 0x4ff4460, 0x196d95e9,
        0x13cd2fcb, 0x18ea1fdc, 0x37f42e3, 0x6f9a37c, 0x1713e479, 0xc,
    ],
    [
        0x10074d8e, 0x103e4526, 0x113581b3, 0x139be836, 0x1643249d, 0x1f3fc88f, 0x918b9af,
        0x17155e18, 0xc523559, 0x1ff6976e, 0xe463050, 0x1e6dedbd, 0xb46a908, 0xc,
    ],
    [
        0xb971ef8, 0xa602780, 0x4847c83, 0x10a38323, 0x633f06c, 0x87403da, 0x23b009c, 0x54684d6,
        0x47aa7b1, 0x27a9fa, 0x14554258, 0x372733, 0x1182cac1, 0x5,
    ],
    [
        0x1b980133, 0x16ce9fae, 0x8ca9910, 0x1f215a38, 0x659cc6c, 0x11969e20, 0x16004f99,
        0x101a982, 0x1c757b3b, 0x13df18ae, 0x1cbf002b, 0x1a3d9536, 0x45a394a, 0x1,
    ],
    [
        0x1475224b, 0x1358f38a, 0x1e6bede1, 0x20936ca, 0x7ce46ba, 0x7ae9cb5, 0x15a366ac,
        0x103afd0c, 0x1c5e673d, 0x1a46251f, 0xa8567d, 0x1c899e22, 0x1c129645, 0x2,
    ],
    [
        0x9c8b604, 0x5a2b5f3, 0x10071dc1, 0xa04fdfd, 0x101b2b66, 0xa7d4ad7, 0x8e55eb7, 0x11f092cb,
        0x15cb181d, 0x1a16f975, 0x13a942ce, 0x121e079c, 0x1e6be4e9, 0xa,
    ],
];
pub const ISO11_YDEN: [[Chunk; NLEN]; 16] = [
    [
        0x103663c1, 0xa3c929d, 0x3081b40, 0x6d11dec, 0x12e7a07f, 0x1195adf3, 0xf9bbb0c, 0x1caf1301,
        0x9601a6d, 0x7d68757, 0x14860450, 0x15393164, 0x112c4c3, 0xb,
    ],
    [
        0xe49a03d, 0x17b08161, 0x14a78d4c, 0x84c0ec6, 0x1e01f78a, 0x1ab7a29, 0x16729284,
        0x1ee6389a, 0x1885c84f, 0x21e1a45, 0x6832f5b, 0x702403c, 0x162d75c2, 0xc,
    ],
    [
        0x1dbf67f2, 0x1129c5a9, 0x1e5be247, 0xaf9ac6d, 0xd2eca67, 0x12ee93ce, 0x1cc430d6,
        0xaaa35cf, 0x1778c485, 0xb74758a, 0x1beaab9f, 0xc81b44e, 0x18df3306, 0x2,
    ],
    [
        0x45f5416, 0x6936cc2, 0xa5eb6a, 0x6c9e585, 0xaf41727, 0x1244f393, 0xc3848f6, 0x1b7bb79a,
        0x11d115c5, 0x1c4f6da6, 0x1c8348ef, 0x131ca72b, 0xb7d2887, 0xb,
    ],
    [
        0x11a5001d, 0x11c8a118, 0x14bb7b76, 0x162bb81f, 0xc916a20, 0xd07e4ef, 0xec150bb,
        0x13e1ed37, 0x1cc6d19c, 0x17c1146e, 0xc033244, 0x8be87c9, 0x1e0e0795, 0x5,
    ],
    [
        0xaf9b7ac, 0x16323bfd, 0xa733880, 0x71b73bf, 0x15a6449f, 0xc3db787, 0x20717b3, 0x18caaa1b,
        0x2b70152, 0x1563c18c, 0x7ec99ba, 0x30db65b, 0xd9e5297, 0x4,
    ],
    [
        0x126a775c, 0x8d09cc8, 0x2c7ee4f, 0x1538034b, 0x51d5f, 0x12de2005, 0x3bd774d, 0x1f51a19f,
        0xb5eecfd, 0x5674c12, 0x10eea1cd, 0x1533b65f, 0x6007c08, 0xb,
    ],
    [
        0x15812ed9, 0x7720ad0, 0x77b918, 0x1eb6010, 0x17132b92, 0x7e9031a, 0x1f5ffacd, 0xbdf43e9,
        0xee5a437, 0x15dd37fb, 0xef377e, 0x1c7d4fd4, 0xa3ef08b, 0xb,
    ],
    [
        0x15535d4a, 0x1919ecea, 0x49220da, 0x1fc5ef77, 0x19b4852c, 0x1a8625f9, 0x482af15,
        0x1c98d5eb, 0x4f9fb0c, 0x1e8eba66, 0x686f953, 0x6d8c246, 0x66c8ed3, 0xc,
    ],
    [
        0x18913f55, 0x377a45d, 0xa6cd78d, 0x10bd47aa, 0x1d4fbc73, 0xc973f53, 0x1eed4c21, 0xc7c27b0,
        0x103216f7, 0x1eca5424, 0x1aa08165, 0xe14dc39, 0x7a55cda, 0xb,
    ],
    [
        0x1a8f6aa8, 0x7c5a4e5, 0xc18100, 0xb853e9f, 0xa5c871a, 0xd9b731b, 0x18a43964, 0x7376c34,
        0x1d9c6dd0, 0xd69488, 0x123c0428, 0x1d480b7a, 0xd2f259e, 0x2,
    ],
    [
        0x2561092, 0x1425a94f, 0x1faefaa5, 0x12d130de, 0x1913516f, 0xd446753, 0xb4a303e,
        0x115df9c8, 0x77f94ff, 0x12462862, 0x1d614b07, 0x103a067f, 0xccbb674, 0x5,
    ],
    [
        0x173345cc, 0x14cd89c2, 0xe42b047, 0xec7c7, 0x19b86930, 0x177cd006, 0x899f573, 0x1b315be0,
        0x16543346, 0x5a2f8a4, 0x10d84c51, 0x18ecffc7, 0xd6b9514, 0x5,
    ],
    [
        0x6ed06f7, 0xfd6e099, 0x5332034, 0xa2f7b0e, 0x480e420, 0x6f93ca1, 0x1f072dd2, 0x129ce524,
        0x12bf565b, 0xa9e6bb7, 0x18a2f743, 0x165c9e76, 0x660400e, 0x1,
    ],
    [
        0x1d634b8f, 0xaa39d0, 0xd25e011, 0x5eae1e2, 0xaa205ca, 0x1e6b1ab6, 0x14cc93b, 0xcbc4e77,
        0x171c40f, 0x106bc0ce, 0x1ac90957, 0xdbb807c, 0xfa1d81, 0x7,
    ],
    [
        0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ],
];