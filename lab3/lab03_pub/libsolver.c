#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dlfcn.h>


// shuffle: ndat[44] = 498 -> calls to code_498 should be code_44
static int ndat[] = { 1425, 1310, 1369, 518, 501, 425, 1108, 503, 939, 268, 1114, 463, 731, 1251, 438, 413, 674, 483, 474, 1112, 1366, 364, 1009, 148, 216, 372, 522, 542, 347, 85, 1146, 1402, 1104, 449, 1286, 627, 283, 92, 471, 169, 1302, 1455, 1306, 898, 498, 271, 1107, 158, 391, 587, 1357, 916, 370, 1249, 1243, 769, 77, 1297, 1230, 251, 418, 314, 973, 13, 996, 667, 638, 191, 1400, 855, 568, 1051, 933, 1023, 1084, 662, 1268, 801, 1026, 785, 842, 1059, 291, 1133, 525, 584, 145, 983, 641, 1374, 1011, 649, 1095, 439, 393, 689, 456, 770, 954, 1415, 154, 856, 974, 448, 466, 1309, 676, 1126, 1106, 480, 218, 805, 1056, 936, 889, 408, 163, 106, 591, 1188, 1353, 97, 362, 729, 807, 159, 543, 339, 124, 925, 1140, 1308, 317, 18, 1339, 1013, 557, 1129, 1390, 990, 761, 1337, 572, 33, 1279, 910, 774, 1097, 1266, 180, 531, 876, 1260, 152, 755, 146, 1237, 1399, 1284, 888, 1377, 1437, 262, 687, 311, 253, 454, 959, 243, 1376, 321, 1193, 509, 847, 726, 1434, 569, 688, 35, 766, 26, 1253, 1475, 369, 850, 1246, 554, 405, 795, 368, 1391, 893, 1407, 1, 685, 551, 879, 300, 1469, 1185, 800, 147, 460, 470, 754, 642, 783, 556, 1428, 1215, 635, 200, 237, 6, 1073, 684, 1417, 1468, 355, 590, 270, 48, 360, 827, 25, 706, 1182, 1451, 571, 699, 23, 944, 1162, 920, 469, 1029, 195, 977, 943, 776, 1120, 285, 304, 407, 529, 1072, 430, 657, 27, 1345, 275, 72, 806, 951, 225, 1012, 343, 51, 1287, 444, 753, 75, 924, 804, 76, 111, 998, 1044, 490, 1010, 224, 290, 1351, 1128, 841, 848, 697, 440, 403, 1164, 319, 371, 1200, 1381, 963, 1304, 1439, 493, 349, 849, 107, 1269, 1319, 1333, 613, 334, 1346, 904, 1406, 1141, 758, 885, 208, 969, 73, 669, 913, 633, 492, 1352, 953, 22, 1401, 351, 594, 422, 151, 255, 535, 1394, 1019, 221, 1272, 1321, 828, 3, 1426, 328, 1016, 1363, 248, 574, 1476, 1055, 157, 894, 1136, 865, 182, 261, 1067, 446, 1300, 256, 1264, 210, 346, 235, 639, 712, 193, 1099, 621, 1380, 1071, 814, 302, 473, 1137, 1008, 995, 45, 822, 19, 704, 607, 505, 659, 519, 260, 949, 378, 1438, 1186, 411, 927, 1361, 500, 489, 421, 399, 238, 381, 870, 1360, 576, 74, 1324, 866, 329, 380, 358, 952, 698, 101, 567, 5, 930, 878, 273, 1444, 816, 1027, 1283, 43, 1355, 562, 409, 203, 1132, 1473, 1064, 784, 826, 1015, 661, 751, 1115, 84, 799, 757, 254, 1105, 1093, 631, 90, 1163, 989, 117, 1184, 1280, 229, 929, 1285, 566, 947, 171, 1045, 829, 1409, 862, 330, 230, 365, 1158, 928, 284, 451, 1315, 606, 1042, 1265, 1213, 265, 1235, 833, 1242, 461, 420, 177, 906, 988, 1263, 748, 1257, 28, 663, 664, 786, 71, 1354, 244, 624, 1397, 511, 486, 891, 1365, 240, 1421, 946, 62, 186, 168, 272, 532, 496, 725, 50, 1229, 324, 112, 719, 609, 142, 1446, 1219, 58, 485, 1445, 1103, 1218, 2, 42, 1144, 417, 81, 1190, 1247, 1311, 922, 1386, 150, 650, 144, 20, 1085, 597, 524, 1356, 176, 646, 1267, 374, 530, 668, 313, 1467, 1419, 9, 779, 234, 1032, 736, 897, 868, 821, 213, 1024, 1069, 1123, 940, 1179, 854, 1035, 767, 149, 173, 1052, 257, 1166, 299, 1149, 1307, 1139, 395, 1418, 899, 214, 915, 427, 860, 671, 578, 1240, 205, 40, 745, 266, 1221, 87, 1314, 113, 563, 561, 1039, 824, 1393, 1470, 37, 131, 760, 901, 634, 1262, 1232, 678, 1131, 1312, 402, 1313, 1255, 1288, 1274, 1124, 333, 1318, 508, 903, 1317, 447, 1135, 1316, 1092, 875, 98, 1454, 1404, 523, 811, 354, 980, 99, 120, 204, 404, 1364, 83, 1195, 170, 436, 1151, 384, 993, 644, 604, 1005, 389, 732, 165, 1422, 960, 958, 516, 520, 956, 1294, 558, 1192, 874, 1443, 526, 911, 11, 962, 161, 1047, 672, 1368, 1050, 1109, 1090, 921, 857, 249, 763, 585, 167, 1152, 1450, 1049, 728, 1343, 1156, 513, 741, 226, 450, 869, 1217, 228, 222, 1256, 1429, 1204, 1117, 546, 1155, 331, 484, 367, 269, 815, 961, 1170, 212, 1291, 1212, 884, 713, 1388, 96, 797, 1278, 738, 1344, 787, 1423, 118, 839, 437, 1436, 1254, 47, 1433, 1191, 1148, 1167, 600, 377, 412, 1259, 872, 1198, 1385, 457, 1208, 1189, 781, 1375, 482, 682, 950, 1258, 636, 7, 573, 539, 817, 709, 1233, 1004, 129, 651, 1020, 426, 1252, 871, 656, 622, 808, 1299, 1379, 1171, 823, 692, 723, 108, 637, 1396, 36, 721, 1463, 338, 1373, 971, 853, 1303, 716, 274, 1007, 851, 1461, 428, 740, 242, 832, 315, 981, 166, 59, 708, 56, 559, 1332, 352, 1203, 1078, 1211, 1074, 718, 160, 115, 287, 1225, 175, 1142, 733, 1442, 1175, 835, 632, 629, 215, 583, 298, 1001, 220, 194, 803, 896, 602, 680, 1094, 1063, 914, 1248, 309, 63, 739, 986, 301, 648, 4, 416, 38, 286, 616, 1176, 462, 424, 630, 1125, 109, 472, 406, 1160, 196, 1222, 945, 488, 185, 1006, 1370, 705, 318, 1270, 1068, 1273, 1335, 174, 844, 679, 1398, 1138, 455, 135, 514, 491, 336, 198, 138, 32, 252, 1169, 931, 997, 136, 1464, 295, 1033, 153, 239, 82, 342, 555, 552, 710, 1206, 1041, 278, 133, 121, 465, 1053, 1347, 119, 21, 1325, 735, 363, 281, 1134, 541, 164, 1413, 580, 61, 396, 337, 789, 280, 912, 941, 414, 792, 1328, 1448, 327, 201, 612, 957, 1424, 57, 601, 179, 1098, 86, 547, 742, 864, 143, 1452, 310, 976, 1465, 991, 756, 772, 812, 858, 344, 545, 820, 429, 1154, 476, 1101, 764, 1021, 873, 1362, 1331, 245, 1238, 126, 527, 423, 1014, 316, 366, 1341, 39, 433, 608, 985, 95, 1040, 376, 1205, 570, 348, 1323, 881, 890, 502, 1412, 677, 236, 359, 598, 966, 1250, 979, 1159, 1147, 1057, 332, 1367, 247, 282, 184, 1119, 845, 1326, 1121, 1261, 1030, 575, 139, 54, 181, 593, 1223, 696, 549, 392, 1111, 104, 1075, 768, 1342, 722, 1060, 859, 206, 481, 701, 673, 596, 497, 478, 1031, 1110, 1201, 432, 41, 1145, 626, 588, 190, 44, 1427, 1194, 232, 919, 752, 443, 353, 788, 955, 132, 1440, 103, 507, 293, 846, 130, 388, 134, 183, 398, 1202, 902, 1227, 695, 67, 1150, 1349, 999, 577, 458, 102, 1118, 1226, 521, 1359, 128, 1022, 618, 459, 714, 1172, 782, 693, 935, 12, 694, 1338, 1209, 410, 1038, 1082, 970, 434, 375, 778, 658, 762, 565, 1177, 65, 793, 819, 1405, 886, 178, 1207, 737, 660, 691, 589, 614, 548, 419, 510, 435, 615, 686, 312, 1239, 1277, 264, 533, 938, 926, 1143, 172, 1350, 10, 78, 323, 1281, 137, 499, 1298, 122, 628, 1003, 1410, 326, 250, 620, 1348, 277, 259, 1054, 1086, 744, 1127, 1122, 1471, 305, 603, 746, 775, 900, 1178, 91, 379, 1282, 49, 468, 1058, 534, 1087, 397, 905, 711, 1457, 1474, 537, 948, 0, 241, 64, 720, 666, 88, 55, 467, 140, 727, 1180, 1411, 1037, 1228, 189, 942, 1395, 68, 771, 619, 813, 258, 114, 1435, 320, 60, 665, 908, 1234, 141, 211, 495, 1276, 231, 322, 70, 759, 1382, 46, 867, 1168, 809, 325, 1080, 1383, 765, 1061, 830, 544, 401, 1214, 1447, 233, 749, 1392, 356, 1456, 564, 887, 188, 155, 123, 834, 863, 504, 1034, 882, 1231, 267, 652, 825, 246, 717, 382, 1076, 1181, 1048, 373, 780, 116, 386, 794, 1199, 992, 515, 1113, 1472, 877, 512, 217, 15, 1378, 1290, 579, 156, 683, 1174, 415, 1000, 30, 1293, 276, 1292, 599, 1245, 307, 1089, 100, 798, 796, 223, 917, 1320, 296, 617, 292, 452, 1216, 340, 79, 790, 1449, 94, 400, 1100, 592, 730, 1244, 199, 923, 1046, 560, 968, 209, 540, 750, 202, 984, 1065, 335, 1224, 978, 655, 1210, 127, 8, 994, 308, 207, 1173, 1336, 1157, 69, 1043, 1305, 675, 1088, 1389, 743, 383, 965, 192, 1384, 1430, 550, 623, 89, 1289, 289, 517, 29, 1330, 595, 105, 909, 17, 610, 16, 1017, 357, 581, 1196, 1301, 1241, 31, 453, 53, 1372, 1036, 715, 1102, 625, 852, 702, 1295, 487, 1431, 345, 707, 1462, 385, 703, 1327, 479, 538, 791, 1322, 303, 24, 838, 1079, 536, 670, 294, 773, 1165, 197, 802, 840, 1371, 441, 263, 553, 387, 837, 1081, 361, 1441, 861, 431, 1466, 1458, 390, 810, 34, 734, 1408, 934, 1187, 1062, 14, 528, 1403, 1334, 66, 1340, 1453, 1414, 777, 306, 464, 1183, 1329, 1161, 975, 1432, 700, 80, 1358, 162, 1236, 110, 918, 52, 647, 987, 506, 892, 494, 880, 1460, 843, 187, 219, 477, 1083, 1416, 1018, 475, 93, 394, 724, 288, 279, 967, 681, 836, 1197, 937, 1296, 831, 645, 1387, 297, 582, 640, 125, 818, 1077, 932, 227, 653, 1153, 747, 1091, 611, 341, 1002, 1130, 1275, 964, 442, 1025, 1220, 445, 1066, 895, 982, 605, 654, 350, 1116, 1028, 643, 1070, 907, 1459, 1420, 690, 1271, 972, 586, 883, 1096 };

// // hardcode: function name -> GOT relative position (local)
// int func2GOTPos[689][2] = {
//     {606, 0x24a08},{641, 0x24a10},{175, 0x24a18},{1272, 0x24a20},{1276, 0x24a28},{286, 0x24a30},{249, 0x24a38},{502, 0x24a40},{284, 0x24a48},{208, 0x24a50},{280, 0x24a58},{541, 0x24a60},{206, 0x24a68},{786, 0x24a70},{1237, 0x24a78},{1008, 0x24a80},{788, 0x24a88},{704, 0x24a90},{741, 0x24a98},{1045, 0x24aa0},{1235, 0x24aa8},{738, 0x24ab0},{706, 0x24ab8},{1239, 0x24ac0},{1152, 0x24ac8},{849, 0x24ad0},{775, 0x24ad8},{1004, 0x24ae0},{1193, 0x24ae8},{1156, 0x24af0},{771, 0x24af8},{1191, 0x24b00},{200, 0x24b08},{380, 0x24b10},{1309, 0x24b18},{1136, 0x24b20},{847, 0x24b28},{877, 0x24b38},{808, 0x24b40},{57, 0x24b48},{1132, 0x24b50},{1134, 0x24b58},{841, 0x24b60},{1348, 0x24b68},{1346, 0x24b70},{10, 0x24b78},{1291, 0x24b80},{884, 0x24b88},{1293, 0x24b90},{1385, 0x24b98},{300, 0x24ba0},{473, 0x24ba8},{1250, 0x24bb0},{304, 0x24bb8},{949, 0x24bc0},{1254, 0x24bc8},{1217, 0x24bd0},{1446, 0x24bd8},{1409, 0x24be0},{1256, 0x24be8},{947, 0x24bf0},{1219, 0x24bf8},{1407, 0x24c00},{1215, 0x24c08},{1448, 0x24c10},{945, 0x24c18},{908, 0x24c20},{906, 0x24c28},{943, 0x24c30},{96, 0x24c38},{986, 0x24c40},{1213, 0x24c48},{180, 0x24c50},{1211, 0x24c58},{141, 0x24c60},{591, 0x24c68},{558, 0x24c70},{108, 0x24c78},{519, 0x24c80},{556, 0x24c88},{432, 0x24c90},{1186, 0x24c98},{597, 0x24ca0},{147, 0x24ca8},{1149, 0x24cb0},{430, 0x24cb8},{92, 0x24cc0},{1147, 0x24cc8},{182, 0x24cd0},{145, 0x24cd8},{631, 0x24ce0},{1188, 0x24ce8},{149, 0x24cf0},{186, 0x24cf8},{1284, 0x24d00},{684, 0x24d08},{238, 0x24d10},{680, 0x24d20},{511, 0x24d28},{273, 0x24d30},{234, 0x24d38},{102, 0x24d40},{271, 0x24d48},{550, 0x24d50},{513, 0x24d58},{799, 0x24d60},{711, 0x24d68},{1019, 0x24d70},{1421, 0x24d78},{28, 0x24d80},{26, 0x24d88},{782, 0x24d90},{1184, 0x24d98},{1015, 0x24da0},{1011, 0x24da8},{1013, 0x24db0},{391, 0x24db8},{317, 0x24dc0},{315, 0x24dc8},{230, 0x24dd0},{866, 0x24dd8},{1332, 0x24de0},{834, 0x24de8},{20, 0x24df0},{22, 0x24df8},{1082, 0x24e00},{871, 0x24e08},{873, 0x24e10},{1260, 0x24e18},{1379, 0x24e20},{1338, 0x24e28},{1221, 0x24e30},{429, 0x24e38},{466, 0x24e40},{1084, 0x24e48},{1373, 0x24e50},{427, 0x24e58},{313, 0x24e60},{311, 0x24e68},{1377, 0x24e70},{1225, 0x24e78},{921, 0x24e80},{1418, 0x24e88},{1451, 0x24e90},{1049, 0x24e98},{1414, 0x24ea0},{953, 0x24ea8},{1160, 0x24eb0},{990, 0x24eb8},{157, 0x24ec0},{568, 0x24ec8},{1457, 0x24ed0},{1121, 0x24ed8},{155, 0x24ee0},{566, 0x24ee8},{67, 0x24ef0},{153, 0x24ef8},{114, 0x24f00},{529, 0x24f08},{527, 0x24f10},{112, 0x24f18},{562, 0x24f20},{460, 0x24f28},{61, 0x24f30},{421, 0x24f38},{1175, 0x24f40},{639, 0x24f48},{676, 0x24f50},{159, 0x24f58},{620, 0x24f60},{637, 0x24f68},{674, 0x24f70},{635, 0x24f78},{624, 0x24f80},{1313, 0x24f88},{1179, 0x24f90},{261, 0x24f98},{226, 0x24fa0},{224, 0x24fa8},{1258, 0x24fb0},{758, 0x24fb8},{720, 0x24fc0},{1026, 0x24fc8},{523, 0x24fd0},{1067, 0x24fd8},{756, 0x24fe0},{265, 0x24fe8},{754, 0x24ff0},{719, 0x24ff8},{1063, 0x25000},{761, 0x25008},{717, 0x25010},{269, 0x25018},{797, 0x25020},{4, 0x25028},{328, 0x25030},{326, 0x25038},{222, 0x25040},{829, 0x25048},{898, 0x25050},{1114, 0x25058},{369, 0x25060},{220, 0x25068},{827, 0x25070},{367, 0x25078},{1321, 0x25080},{825, 0x25088},{851, 0x25090},{814, 0x25098},{2, 0x250a0},{1360, 0x250a8},{823, 0x250b0},{33, 0x250b8},{1093, 0x250c0},{1232, 0x250c8},{862, 0x250d0},{864, 0x250d8},{1362, 0x250e0},{457, 0x250e8},{1230, 0x250f0},{1097, 0x250f8},{860, 0x25100},{1095, 0x25108},{492, 0x25110},{418, 0x25118},{416, 0x25120},{451, 0x25128},{1056, 0x25130},{1423, 0x25138},{1368, 0x25140},{320, 0x25148},{1234, 0x25150},{929, 0x25158},{498, 0x25160},{1099, 0x25168},{927, 0x25170},{925, 0x25178},{1464, 0x25180},{1468, 0x25188},{129, 0x25190},{960, 0x25198},{1110, 0x251a0},{164, 0x251a8},{577, 0x251b0},{76, 0x251b8},{538, 0x251c0},{575, 0x251c8},{160, 0x251d0},{573, 0x251d8},{70, 0x251e0},{412, 0x251e8},{1306, 0x251f0},{698, 0x251f8},{651, 0x25200},{1125, 0x25208},{628, 0x25210},{663, 0x25218},{1300, 0x25220},{1129, 0x25228},{661, 0x25230},{1304, 0x25238},{299, 0x25240},{254, 0x25248},{1266, 0x25250},{1264, 0x25258},{534, 0x25260},{571, 0x25268},{769, 0x25270},{776, 0x25278},{1074, 0x25280},{293, 0x25288},{532, 0x25290},{1406, 0x25298},{291, 0x252a0},{1268, 0x252a8},{47, 0x252b0},{1072, 0x252b8},{728, 0x252c0},{1035, 0x252c8},{1229, 0x252d0},{726, 0x252d8},{6, 0x252e0},{1166, 0x252e8},{1400, 0x252f0},{374, 0x252f8},{339, 0x25300},{337, 0x25308},{801, 0x25310},{1144, 0x25318},{1107, 0x25320},{1356, 0x25328},{857, 0x25330},{1354, 0x25338},{1317, 0x25340},{45, 0x25348},{1142, 0x25350},{805, 0x25358},{1105, 0x25360},{855, 0x25368},{43, 0x25370},{853, 0x25378},{816, 0x25380},{894, 0x25388},{896, 0x25390},{1103, 0x25398},{892, 0x253a0},{1391, 0x253a8},{1101, 0x253b0},{448, 0x253b8},{446, 0x253c0},{409, 0x253c8},{1399, 0x253d0},{407, 0x253d8},{1434, 0x253e0},{1069, 0x253e8},{333, 0x253f0},{1246, 0x253f8},{1395, 0x25400},{331, 0x25408},{989, 0x25410},{901, 0x25418},{1471, 0x25420},{933, 0x25428},{903, 0x25430},{1242, 0x25438},{1203, 0x25440},{489, 0x25448},{1436, 0x25450},{1473, 0x25460},{974, 0x25468},{970, 0x25470},{1475, 0x25478},{583, 0x25480},{133, 0x25488},{548, 0x25490},{581, 0x25498},{546, 0x254a0},{84, 0x254a8},{1140, 0x254b0},{509, 0x254b8},{601, 0x254c0},{139, 0x254d0},{687, 0x254d8},{440, 0x254e0},{403, 0x254e8},{1116, 0x254f0},{659, 0x254f8},{1331, 0x25500},{642, 0x25508},{607, 0x25510},{657, 0x25518},{176, 0x25520},{1273, 0x25528},{692, 0x25530},{285, 0x25538},{248, 0x25540},{1040, 0x25550},{283, 0x25558},{244, 0x25560},{501, 0x25568},{242, 0x25570},{739, 0x25578},{785, 0x25580},{505, 0x25588},{701, 0x25590},{287, 0x25598},{787, 0x255a0},{1279, 0x255a8},{58, 0x255b0},{1007, 0x255b8},{772, 0x255c0},{1001, 0x255c8},{1151, 0x255d0},{50, 0x255d8},{1192, 0x255e0},{240, 0x255e8},{203, 0x255f0},{307, 0x255f8},{15, 0x25600},{201, 0x25608},{876, 0x25610},{1194, 0x25618},{1345, 0x25620},{1137, 0x25628},{56, 0x25630},{1308, 0x25638},{1133, 0x25640},{1347, 0x25648},{807, 0x25650},{842, 0x25658},{885, 0x25660},{1198, 0x25668},{1388, 0x25670},{1380, 0x25678},{439, 0x25680},{437, 0x25688},{470, 0x25690},{433, 0x25698},{1445, 0x256a0},{340, 0x256a8},{1255, 0x256b0},{1218, 0x256b8},{1386, 0x256c0},{956, 0x256c8},{946, 0x256d0},{993, 0x256d8},{1212, 0x256e0},{944, 0x256e8},{995, 0x256f0},{97, 0x256f8},{1251, 0x25700},{1253, 0x25708},{983, 0x25710},{95, 0x25718},{985, 0x25720},{144, 0x25728},{981, 0x25730},{142, 0x25738},{109, 0x25740},{590, 0x25748},{557, 0x25750},{518, 0x25758},{598, 0x25760},{185, 0x25768},{1148, 0x25770},{630, 0x25778},{183, 0x25780},{648, 0x25788},{632, 0x25790},{189, 0x25798},{634, 0x257a0},{646, 0x257a8},{1189, 0x257b0},{1090, 0x257b8},{609, 0x257c0},{683, 0x257c8},{685, 0x257d0},{1283, 0x257d8},{1051, 0x257e0},{235, 0x257e8},{512, 0x257f0},{272, 0x257f8},{1285, 0x25800},{101, 0x25808},{551, 0x25810},{710, 0x25818},{748, 0x25820},{278, 0x25828},{239, 0x25830},{712, 0x25838},{709, 0x25840},{1287, 0x25848},{25, 0x25850},{744, 0x25858},{707, 0x25860},{1016, 0x25868},{1185, 0x25870},{1012, 0x25878},{783, 0x25880},{396, 0x25888},{318, 0x25890},{355, 0x25898},{27, 0x258a0},{1333, 0x258a8},{23, 0x258b0},{1337, 0x258b8},{822, 0x258c0},{1370, 0x258c8},{1335, 0x258d0},{872, 0x258d8},{1374, 0x258e0},{1085, 0x258e8},{870, 0x258f0},{469, 0x258f8},{467, 0x25900},{351, 0x25908},{919, 0x25910},{1413, 0x25918},{920, 0x25920},{1450, 0x25928},{969, 0x25930},{1415, 0x25938},{999, 0x25940},{952, 0x25948},{954, 0x25950},{117, 0x25958},{567, 0x25960},{1120, 0x25968},{154, 0x25970},{950, 0x25978},{115, 0x25980},{1454, 0x25988},{1419, 0x25990},{152, 0x25998},{528, 0x259a0},{563, 0x259a8},{113, 0x259b0},{111, 0x259b8},{561, 0x259c0},{62, 0x259c8},{424, 0x259d0},{461, 0x259d8},{1351, 0x259e0},{621, 0x259e8},{677, 0x259f0},{158, 0x259f8},{1316, 0x25a00},{1353, 0x25a08},{569, 0x25a10},{660, 0x25a18},{199, 0x25a20},{1312, 0x25a28},{636, 0x25a30},{1176, 0x25a38},{1310, 0x25a40},{262, 0x25a48},{520, 0x25a50},{260, 0x25a58},{757, 0x25a60},{1027, 0x25a68},{1259, 0x25a70},{1021, 0x25a78},{718, 0x25a80},{753, 0x25a88},{716, 0x25a90},{751, 0x25a98},{1023, 0x25aa0},{760, 0x25aa8},{1064, 0x25ab0},{794, 0x25ab8},{796, 0x25ac0},{329, 0x25ac8},{5, 0x25ad0},{360, 0x25ad8},{38, 0x25ae0},{897, 0x25ae8},{368, 0x25af0},{221, 0x25af8},{1115, 0x25b00},{828, 0x25b08},{366, 0x25b10},{1, 0x25b18},{1363, 0x25b20},{3, 0x25b28},{811, 0x25b30},{1326, 0x25b38},{850, 0x25b40},{1361, 0x25b48},{1324, 0x25b50},{1365, 0x25b58},{30, 0x25b60},{865, 0x25b68},{497, 0x25b70},{1231, 0x25b78},{321, 0x25b80},{1424, 0x25b88},{499, 0x25b90},{1055, 0x25b98},{1422, 0x25ba0},{930, 0x25ba8},{1059, 0x25bb0},{1426, 0x25bb8},{924, 0x25bc0},{961, 0x25bc8},{963, 0x25bd0},{1469, 0x25bd8},{77, 0x25be0},{1098, 0x25be8},{1461, 0x25bf0},{1111, 0x25bf8},{163, 0x25c00},{126, 0x25c08},{539, 0x25c10},{576, 0x25c18},{1463, 0x25c20},{537, 0x25c28},{124, 0x25c30},{574, 0x25c38},{411, 0x25c40},{73, 0x25c48},{572, 0x25c50},{75, 0x25c58},{450, 0x25c60},{415, 0x25c68},{1126, 0x25c70},{71, 0x25c78},{1467, 0x25c80},{169, 0x25c88},{413, 0x25c90},{697, 0x25c98},{1342, 0x25ca0},{167, 0x25ca8},{650, 0x25cb0},{613, 0x25cb8},{1169, 0x25cc0},{699, 0x25cc8},{629, 0x25cd0},{1128, 0x25cd8},{662, 0x25ce0},{1263, 0x25ce8},{290, 0x25cf0},{218, 0x25cf8},{533, 0x25d00},{120, 0x25d08},{777, 0x25d10},{259, 0x25d18},{531, 0x25d20},{766, 0x25d28},{729, 0x25d30},{779, 0x25d38},{257, 0x25d40},{1226, 0x25d48},{1032, 0x25d50},{764, 0x25d58},{1071, 0x25d60},{1034, 0x25d68},{762, 0x25d70},{48, 0x25d78},{1401, 0x25d80},{1073, 0x25d88},{1163, 0x25d90},{7, 0x25da0},{1167, 0x25da8},{1269, 0x25db0},{1165, 0x25db8},{338, 0x25dc0},{334, 0x25dc8},{1318, 0x25dd0},{1355, 0x25dd8},{212, 0x25de0},{377, 0x25de8},{800, 0x25df0},{856, 0x25df8},{375, 0x25e00},{1390, 0x25e08},{817, 0x25e10},{854, 0x25e18},{852, 0x25e20},{1143, 0x25e28},{1359, 0x25e30},{1106, 0x25e38},{1398, 0x25e40},{44, 0x25e48},{1280, 0x25e50},{893, 0x25e58},{1396, 0x25e60},{1282, 0x25e68},{1394, 0x25e70},{891, 0x25e78},{482, 0x25e80},{480, 0x25e88},{408, 0x25e90},{332, 0x25e98},{988, 0x25ea0},{900, 0x25ea8},{330, 0x25eb0},{1206, 0x25eb8},{902, 0x25ec0},{1247, 0x25ec8},{1068, 0x25ed0},{936, 0x25ed8},{1208, 0x25ee0},{1433, 0x25ee8},{1243, 0x25ef0},{1204, 0x25ef8},{1437, 0x25f00},{932, 0x25f08},{1182, 0x25f10},{87, 0x25f18},{977, 0x25f28},{1202, 0x25f30},{179, 0x25f38},{971, 0x25f40},{134, 0x25f48},{584, 0x25f50},{1180, 0x25f58},{1200, 0x25f60},{132, 0x25f68},{545, 0x25f70},{508, 0x25f78},{543, 0x25f80},{443, 0x25f88},{406, 0x25f90},{1117, 0x25f98},{81, 0x25fa0},{173, 0x25fa8},{1476, 0x25fb0},{171, 0x25fb8},{688, 0x25fc0}
// };
// size_t GOTSize = 0x25fc0 - 0x24a00;

// hardcode: function name -> GOT relative position (x86)
int func2GOTPos[689][2] = {
    {606, 0x17a30},{641, 0x17a38},{175, 0x17a40},{1272, 0x17a48},{1276, 0x17a50},{286, 0x17a58},{249, 0x17a60},{502, 0x17a68},{284, 0x17a70},{208, 0x17a78},{280, 0x17a80},{541, 0x17a88},{206, 0x17a90},{786, 0x17a98},{1237, 0x17aa0},{1008, 0x17aa8},{788, 0x17ab0},{704, 0x17ab8},{741, 0x17ac0},{1045, 0x17ac8},{1235, 0x17ad0},{738, 0x17ad8},{706, 0x17ae0},{1239, 0x17ae8},{1152, 0x17af0},{849, 0x17af8},{775, 0x17b00},{1004, 0x17b08},{1193, 0x17b10},{1156, 0x17b18},{771, 0x17b20},{1191, 0x17b28},{200, 0x17b30},{380, 0x17b38},{1309, 0x17b40},{1136, 0x17b48},{847, 0x17b50},{877, 0x17b58},{808, 0x17b60},{57, 0x17b68},{1132, 0x17b70},{1134, 0x17b78},{841, 0x17b80},{1348, 0x17b88},{1346, 0x17b90},{10, 0x17b98},{1291, 0x17ba0},{884, 0x17ba8},{1293, 0x17bb0},{1385, 0x17bb8},{300, 0x17bc0},{473, 0x17bc8},{1250, 0x17bd0},{304, 0x17bd8},{949, 0x17be0},{1254, 0x17be8},{1217, 0x17bf0},{1446, 0x17bf8},{1409, 0x17c00},{1256, 0x17c08},{947, 0x17c10},{1219, 0x17c18},{1407, 0x17c20},{1215, 0x17c28},{1448, 0x17c30},{945, 0x17c38},{908, 0x17c40},{906, 0x17c48},{943, 0x17c50},{96, 0x17c58},{986, 0x17c60},{1213, 0x17c68},{180, 0x17c70},{1211, 0x17c78},{141, 0x17c80},{591, 0x17c88},{558, 0x17c90},{108, 0x17c98},{519, 0x17ca0},{556, 0x17ca8},{432, 0x17cb0},{1186, 0x17cb8},{597, 0x17cc0},{147, 0x17cc8},{1149, 0x17cd0},{430, 0x17cd8},{92, 0x17ce0},{1147, 0x17ce8},{182, 0x17cf0},{145, 0x17cf8},{631, 0x17d00},{1188, 0x17d08},{149, 0x17d10},{186, 0x17d18},{1284, 0x17d20},{684, 0x17d28},{238, 0x17d30},{680, 0x17d38},{511, 0x17d40},{273, 0x17d48},{234, 0x17d50},{102, 0x17d58},{271, 0x17d60},{550, 0x17d68},{513, 0x17d70},{799, 0x17d78},{711, 0x17d80},{1019, 0x17d88},{1421, 0x17d90},{28, 0x17d98},{26, 0x17da0},{782, 0x17da8},{1184, 0x17db0},{1015, 0x17db8},{1011, 0x17dc0},{1013, 0x17dc8},{391, 0x17dd0},{317, 0x17dd8},{315, 0x17de0},{230, 0x17de8},{866, 0x17df0},{1332, 0x17df8},{834, 0x17e00},{20, 0x17e08},{22, 0x17e10},{1082, 0x17e18},{871, 0x17e20},{873, 0x17e28},{1260, 0x17e30},{1379, 0x17e38},{1338, 0x17e40},{1221, 0x17e48},{429, 0x17e50},{466, 0x17e58},{1084, 0x17e60},{1373, 0x17e68},{427, 0x17e70},{313, 0x17e78},{311, 0x17e80},{1377, 0x17e88},{1225, 0x17e90},{921, 0x17e98},{1418, 0x17ea0},{1451, 0x17ea8},{1049, 0x17eb0},{1414, 0x17eb8},{953, 0x17ec0},{1160, 0x17ec8},{990, 0x17ed0},{157, 0x17ed8},{568, 0x17ee0},{1457, 0x17ee8},{1121, 0x17ef0},{155, 0x17ef8},{566, 0x17f00},{67, 0x17f08},{153, 0x17f10},{114, 0x17f18},{529, 0x17f20},{527, 0x17f28},{112, 0x17f30},{562, 0x17f38},{460, 0x17f40},{61, 0x17f48},{421, 0x17f50},{1175, 0x17f58},{639, 0x17f60},{676, 0x17f68},{159, 0x17f70},{620, 0x17f78},{637, 0x17f80},{674, 0x17f88},{635, 0x17f90},{624, 0x17f98},{1313, 0x17fa0},{1179, 0x17fa8},{261, 0x17fb0},{226, 0x17fb8},{224, 0x17fc8},{1258, 0x17fd0},{758, 0x17fd8},{720, 0x17fe0},{1026, 0x17fe8},{523, 0x17ff0},{1067, 0x17ff8},{756, 0x18000},{265, 0x18008},{754, 0x18010},{719, 0x18018},{1063, 0x18020},{761, 0x18028},{717, 0x18030},{269, 0x18038},{797, 0x18040},{4, 0x18048},{328, 0x18050},{326, 0x18058},{222, 0x18060},{829, 0x18068},{898, 0x18070},{1114, 0x18078},{369, 0x18080},{220, 0x18088},{827, 0x18090},{367, 0x18098},{1321, 0x180a0},{825, 0x180a8},{851, 0x180b0},{814, 0x180b8},{2, 0x180c0},{1360, 0x180c8},{823, 0x180d0},{33, 0x180d8},{1093, 0x180e0},{1232, 0x180e8},{862, 0x180f0},{864, 0x180f8},{1362, 0x18100},{457, 0x18108},{1230, 0x18110},{1097, 0x18118},{860, 0x18120},{1095, 0x18128},{492, 0x18130},{418, 0x18138},{416, 0x18140},{451, 0x18148},{1056, 0x18150},{1423, 0x18158},{1368, 0x18160},{320, 0x18168},{1234, 0x18170},{929, 0x18178},{498, 0x18180},{1099, 0x18188},{927, 0x18190},{925, 0x18198},{1464, 0x181a0},{1468, 0x181a8},{129, 0x181b0},{960, 0x181b8},{1110, 0x181c0},{164, 0x181c8},{577, 0x181d0},{76, 0x181d8},{538, 0x181e0},{575, 0x181e8},{160, 0x181f0},{573, 0x181f8},{70, 0x18200},{412, 0x18208},{1306, 0x18210},{698, 0x18218},{651, 0x18220},{1125, 0x18228},{628, 0x18230},{663, 0x18238},{1300, 0x18240},{1129, 0x18248},{661, 0x18250},{1304, 0x18258},{299, 0x18260},{254, 0x18268},{1266, 0x18270},{1264, 0x18278},{534, 0x18280},{571, 0x18288},{769, 0x18290},{776, 0x18298},{1074, 0x182a0},{293, 0x182a8},{532, 0x182b0},{1406, 0x182b8},{291, 0x182c0},{1268, 0x182c8},{47, 0x182d0},{1072, 0x182d8},{728, 0x182e0},{1035, 0x182e8},{1229, 0x182f0},{726, 0x182f8},{6, 0x18300},{1166, 0x18308},{1400, 0x18310},{374, 0x18318},{339, 0x18320},{337, 0x18328},{801, 0x18330},{1144, 0x18338},{1107, 0x18340},{1356, 0x18348},{857, 0x18350},{1354, 0x18358},{1317, 0x18360},{45, 0x18368},{1142, 0x18370},{805, 0x18378},{1105, 0x18380},{855, 0x18388},{43, 0x18390},{853, 0x18398},{816, 0x183a0},{894, 0x183a8},{896, 0x183b0},{1103, 0x183b8},{892, 0x183c0},{1391, 0x183c8},{1101, 0x183d0},{448, 0x183d8},{446, 0x183e0},{409, 0x183e8},{1399, 0x183f0},{407, 0x183f8},{1434, 0x18400},{1069, 0x18408},{333, 0x18410},{1246, 0x18418},{1395, 0x18428},{331, 0x18430},{989, 0x18438},{901, 0x18440},{1471, 0x18448},{933, 0x18450},{903, 0x18458},{1242, 0x18460},{1203, 0x18468},{489, 0x18470},{1436, 0x18478},{1473, 0x18480},{974, 0x18488},{970, 0x18490},{1475, 0x18498},{583, 0x184a0},{133, 0x184a8},{548, 0x184b0},{581, 0x184b8},{546, 0x184c0},{84, 0x184c8},{1140, 0x184d0},{509, 0x184d8},{601, 0x184e0},{139, 0x184e8},{687, 0x184f0},{440, 0x184f8},{403, 0x18500},{1116, 0x18508},{659, 0x18510},{1331, 0x18518},{642, 0x18520},{607, 0x18528},{657, 0x18530},{176, 0x18538},{1273, 0x18540},{692, 0x18548},{285, 0x18550},{248, 0x18558},{1040, 0x18568},{283, 0x18570},{244, 0x18578},{501, 0x18580},{242, 0x18588},{739, 0x18590},{785, 0x18598},{505, 0x185a0},{701, 0x185a8},{287, 0x185b0},{787, 0x185b8},{1279, 0x185c0},{58, 0x185c8},{1007, 0x185d0},{772, 0x185d8},{1001, 0x185e0},{1151, 0x185e8},{50, 0x185f0},{1192, 0x185f8},{240, 0x18600},{203, 0x18608},{307, 0x18610},{15, 0x18618},{201, 0x18620},{876, 0x18628},{1194, 0x18630},{1345, 0x18638},{1137, 0x18640},{56, 0x18648},{1308, 0x18650},{1133, 0x18658},{1347, 0x18660},{807, 0x18668},{842, 0x18670},{885, 0x18678},{1198, 0x18680},{1388, 0x18688},{1380, 0x18690},{439, 0x18698},{437, 0x186a0},{470, 0x186a8},{433, 0x186b0},{1445, 0x186b8},{340, 0x186c0},{1255, 0x186c8},{1218, 0x186d0},{1386, 0x186d8},{956, 0x186e0},{946, 0x186e8},{993, 0x186f0},{1212, 0x186f8},{944, 0x18700},{995, 0x18708},{97, 0x18710},{1251, 0x18718},{1253, 0x18720},{983, 0x18728},{95, 0x18730},{985, 0x18738},{144, 0x18740},{981, 0x18748},{142, 0x18750},{109, 0x18758},{590, 0x18760},{557, 0x18768},{518, 0x18770},{598, 0x18778},{185, 0x18780},{1148, 0x18788},{630, 0x18790},{183, 0x18798},{648, 0x187a0},{632, 0x187a8},{189, 0x187b0},{634, 0x187b8},{646, 0x187c0},{1189, 0x187c8},{1090, 0x187d0},{609, 0x187d8},{683, 0x187e0},{685, 0x187e8},{1283, 0x187f0},{1051, 0x187f8},{235, 0x18800},{512, 0x18808},{272, 0x18810},{1285, 0x18818},{101, 0x18820},{551, 0x18828},{710, 0x18830},{748, 0x18838},{278, 0x18840},{239, 0x18848},{712, 0x18850},{709, 0x18858},{1287, 0x18860},{25, 0x18868},{744, 0x18870},{707, 0x18878},{1016, 0x18880},{1185, 0x18888},{1012, 0x18890},{783, 0x18898},{396, 0x188a0},{318, 0x188a8},{355, 0x188b0},{27, 0x188b8},{1333, 0x188c0},{23, 0x188c8},{1337, 0x188d0},{822, 0x188d8},{1370, 0x188e0},{1335, 0x188e8},{872, 0x188f0},{1374, 0x188f8},{1085, 0x18900},{870, 0x18908},{469, 0x18910},{467, 0x18918},{351, 0x18920},{919, 0x18928},{1413, 0x18930},{920, 0x18938},{1450, 0x18940},{969, 0x18948},{1415, 0x18950},{999, 0x18958},{952, 0x18960},{954, 0x18968},{117, 0x18970},{567, 0x18978},{1120, 0x18980},{154, 0x18988},{950, 0x18990},{115, 0x18998},{1454, 0x189a0},{1419, 0x189a8},{152, 0x189b0},{528, 0x189b8},{563, 0x189c0},{113, 0x189c8},{111, 0x189d0},{561, 0x189d8},{62, 0x189e0},{424, 0x189e8},{461, 0x189f0},{1351, 0x189f8},{621, 0x18a00},{677, 0x18a08},{158, 0x18a10},{1316, 0x18a18},{1353, 0x18a20},{569, 0x18a28},{660, 0x18a30},{199, 0x18a38},{1312, 0x18a40},{636, 0x18a48},{1176, 0x18a50},{1310, 0x18a58},{262, 0x18a60},{520, 0x18a68},{260, 0x18a70},{757, 0x18a78},{1027, 0x18a80},{1259, 0x18a88},{1021, 0x18a90},{718, 0x18a98},{753, 0x18aa0},{716, 0x18aa8},{751, 0x18ab0},{1023, 0x18ab8},{760, 0x18ac0},{1064, 0x18ac8},{794, 0x18ad0},{796, 0x18ad8},{329, 0x18ae0},{5, 0x18ae8},{360, 0x18af0},{38, 0x18af8},{897, 0x18b00},{368, 0x18b08},{221, 0x18b10},{1115, 0x18b18},{828, 0x18b20},{366, 0x18b28},{1, 0x18b30},{1363, 0x18b38},{3, 0x18b40},{811, 0x18b48},{1326, 0x18b50},{850, 0x18b58},{1361, 0x18b60},{1324, 0x18b68},{1365, 0x18b70},{30, 0x18b78},{865, 0x18b80},{497, 0x18b88},{1231, 0x18b90},{321, 0x18b98},{1424, 0x18ba0},{499, 0x18ba8},{1055, 0x18bb0},{1422, 0x18bb8},{930, 0x18bc0},{1059, 0x18bc8},{1426, 0x18bd0},{924, 0x18bd8},{961, 0x18be0},{963, 0x18be8},{1469, 0x18bf0},{77, 0x18bf8},{1098, 0x18c00},{1461, 0x18c08},{1111, 0x18c10},{163, 0x18c18},{126, 0x18c20},{539, 0x18c28},{576, 0x18c30},{1463, 0x18c38},{537, 0x18c40},{124, 0x18c48},{574, 0x18c50},{411, 0x18c58},{73, 0x18c60},{572, 0x18c68},{75, 0x18c70},{450, 0x18c78},{415, 0x18c80},{1126, 0x18c88},{71, 0x18c90},{1467, 0x18c98},{169, 0x18ca0},{413, 0x18ca8},{697, 0x18cb0},{1342, 0x18cb8},{167, 0x18cc0},{650, 0x18cc8},{613, 0x18cd0},{1169, 0x18cd8},{699, 0x18ce0},{629, 0x18ce8},{1128, 0x18cf0},{662, 0x18cf8},{1263, 0x18d00},{290, 0x18d08},{218, 0x18d10},{533, 0x18d18},{120, 0x18d20},{777, 0x18d28},{259, 0x18d30},{531, 0x18d38},{766, 0x18d40},{729, 0x18d48},{779, 0x18d50},{257, 0x18d58},{1226, 0x18d60},{1032, 0x18d68},{764, 0x18d70},{1071, 0x18d78},{1034, 0x18d80},{762, 0x18d88},{48, 0x18d90},{1401, 0x18d98},{1073, 0x18da0},{1163, 0x18da8},{7, 0x18db0},{1167, 0x18db8},{1269, 0x18dc0},{1165, 0x18dc8},{338, 0x18dd0},{334, 0x18dd8},{1318, 0x18de0},{1355, 0x18de8},{212, 0x18df0},{377, 0x18df8},{800, 0x18e00},{856, 0x18e08},{375, 0x18e10},{1390, 0x18e18},{817, 0x18e20},{854, 0x18e28},{852, 0x18e30},{1143, 0x18e38},{1359, 0x18e40},{1106, 0x18e48},{1398, 0x18e50},{44, 0x18e58},{1280, 0x18e60},{893, 0x18e68},{1396, 0x18e70},{1282, 0x18e78},{1394, 0x18e80},{891, 0x18e88},{482, 0x18e90},{480, 0x18e98},{408, 0x18ea0},{332, 0x18ea8},{988, 0x18eb0},{900, 0x18eb8},{330, 0x18ec0},{1206, 0x18ec8},{902, 0x18ed0},{1247, 0x18ed8},{1068, 0x18ee0},{936, 0x18ee8},{1208, 0x18ef0},{1433, 0x18ef8},{1243, 0x18f00},{1204, 0x18f08},{1437, 0x18f10},{932, 0x18f18},{1182, 0x18f20},{87, 0x18f28},{977, 0x18f30},{1202, 0x18f38},{179, 0x18f40},{971, 0x18f48},{134, 0x18f50},{584, 0x18f58},{1180, 0x18f60},{1200, 0x18f68},{132, 0x18f70},{545, 0x18f78},{508, 0x18f80},{543, 0x18f88},{443, 0x18f90},{406, 0x18f98},{1117, 0x18fa0},{81, 0x18fa8},{173, 0x18fb0},{1476, 0x18fb8},{171, 0x18fc0},{688, 0x18fc8}
};
size_t GOTSize = 0x18fc8 - 0x17a30; 

char* getBaseAddr() {  // open /proc/self/maps to get the base address of /chals
    FILE *fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t readBuf;
    fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) exit(EXIT_FAILURE);

    char* currBaseAddr = NULL;
    char* currFileName = NULL;
    while((readBuf = getline(&line, &len, fp)) != -1) {
        // parse the string in /proc/self/maps line by line
        char* parseStr = strtok(line, " ");
        currBaseAddr = parseStr;
        while(parseStr != NULL) {
            parseStr = strtok(NULL, " ");
            if(parseStr != NULL) currFileName = parseStr;
        }
        if(strstr(currFileName, "/chals")) break;  // check whether it is /chals info
    }
    fclose(fp);
    
    char* baseAddr = strtok(currBaseAddr, "-");
    return baseAddr;
}

int getRealFuncNum(int originalNum) {  // from ndat (shuffle), get the real function number which should be called
    int functionNum = 1477; // 0 ~ 1476
    for(int i = 0; i < functionNum; i++) {
        if(ndat[i] == originalNum) return i;
    }
    perror("getRealFuncNum didn't find answer");
}

void getRealFuncName(int idx, char* ans) {  // get the function name from the idx (function number)
    char str[6];
    sprintf(str, "%d", idx);
    strcpy(ans, "code_");
    strcat(ans, str);
}

int init() {  // cannot use main, use init to preload
    // printf("* enter init in libsolver *\n");
    setvbuf(stdout, NULL, _IONBF, 0);  // set no buffer

    char* baseAddr = getBaseAddr();
    printf("base address: %s\n", baseAddr);

    // int removeProtection = 0;  // use mprotect only 1 time

    // start parsing the hardcode string
    // start iterating the hardcode string
    for(int i = 0; i < 689; i++) {
        int originalNum = func2GOTPos[i][0];
        int GOTPos = func2GOTPos[i][1];

        // get the real function which should be used
        int realNum = getRealFuncNum(originalNum);
        char realFuncName[10];
        getRealFuncName(realNum, realFuncName);

        // get the real function's address
        void *lib_handle;
        void (*realFuncAddr)();
        char *error;
        // load the shared library
        lib_handle = dlopen("libpoem.so", RTLD_LAZY);
        if (!lib_handle) {
            fprintf(stderr, "%s\n", dlerror());
        }
        // get the function address
        realFuncAddr = dlsym(lib_handle, realFuncName);
        if ((error = dlerror()) != NULL) {
            fprintf(stderr, "%s\n", error);
        }
        dlclose(lib_handle);

        // calculate the GOT address of the original function
        uintptr_t baseAddrNew = (uintptr_t)strtol(baseAddr, NULL, 16);
        uintptr_t GOTPosNew = (uintptr_t)GOTPos;
        void** GOTEntry = (void **)(baseAddrNew + GOTPosNew);

        // modify GOT table with the real function's address
        if(i == 0) {
            // int pagesize = sysconf(_SC_PAGE_SIZE);
            int pagesize = getpagesize();
            // if(pagesize == -1) {
            //     perror("sysconf");
            // }
            int GOTPageNum = (GOTSize + pagesize - 1) / pagesize;

            uintptr_t GOTStartAddr = baseAddrNew + GOTPosNew;  // the first one
            uintptr_t alignAddr = GOTStartAddr & ~(0xFFF);  // !!!!
            printf("GOT Entry: %p\n", (void **)GOTStartAddr);
            printf("aligned addr: %p\n", (void **)alignAddr);

            if(mprotect((void **)alignAddr, pagesize * GOTPageNum, (PROT_READ | PROT_WRITE | PROT_EXEC)) == -1) {
                perror("mprotect");
            }
        }
        // printf("GOT Entry: %p\n", GOTEntry);
        // printf("GOT Entry Content: %p\n", *GOTEntry);
        // printf("real Func addr: %p\n", realFuncAddr);
        memcpy(GOTEntry, &realFuncAddr, 8);
        // printf("GOT Entry Content new: %p\n", *GOTEntry);  // check
    }
    printf("* end of libsolver *\n");
    return 0;
}