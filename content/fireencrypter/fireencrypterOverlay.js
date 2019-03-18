/*
	FIRE ENCRYPTER BUILD 2.9 / 3.0 / 5.0
	Created: September 2007
	Last Update: 05 October 2011
	By Alexandra van den Heetkamp.
*/

(function (global) {

	global.PR_UINT32_MAX = 0xffffffff;
	
	global.BLOCK_SIZE = 16;
	global.ROUNDS = 16;
	global.MAX_ROUNDS = 16;
	
	global.INPUT_WHITEN = 0;
	global.OUTPUT_WHITEN = INPUT_WHITEN + BLOCK_SIZE / 4;
	global.ROUND_SUBKEYS = OUTPUT_WHITEN + BLOCK_SIZE / 4;
	
	global.TOTAL_SUBKEYS = ROUND_SUBKEYS + 2 * MAX_ROUNDS;
	
	global.SK_STEP = 0x02020202;
	global.SK_BUMP = 0x01010101;
	global.SK_ROTL = 9;
	global.P_00 = 1;
	global.P_01 = 0;
	global.P_02 = 0;
	global.P_03 = P_01 ^ 1;
	global.P_04 = 1;
	
	global.P_10 = 0;
	global.P_11 = 0;
	global.P_12 = 1;
	global.P_13 = P_11 ^ 1;
	global.P_14 = 0;
	
	global.P_20 = 1;
	global.P_21 = 1;
	global.P_22 = 0;
	global.P_23 = P_21 ^ 1;
	global.P_24 = 0;
	
	global.P_30 = 0;
	global.P_31 = 1;
	global.P_32 = 1;
	global.P_33 = P_31 ^ 1;
	global.P_34 = 1;
	
	global.GF256_FDBK = 0x169;
	global.GF256_FDBK_2 = 0x169 >>> 1; //$ 0x169/2
	global.GF256_FDBK_4 = 0x169 >>> 2; //$ 0x169/4
	global.MDS = new Array(4 * 256);
	global.RS_GF_FDBK = 0x14D;
	
	global.passg = generate_pass(8, 1);
	global.NumChars = 8;
	global.PassMethod = 1;
	
	global.Sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
	
	global.Rcon = [
		[0x00, 0x00, 0x00, 0x00],
		[0x01, 0x00, 0x00, 0x00],
		[0x02, 0x00, 0x00, 0x00],
		[0x04, 0x00, 0x00, 0x00],
		[0x08, 0x00, 0x00, 0x00],
		[0x10, 0x00, 0x00, 0x00],
		[0x20, 0x00, 0x00, 0x00],
		[0x40, 0x00, 0x00, 0x00],
		[0x80, 0x00, 0x00, 0x00],
		[0x1b, 0x00, 0x00, 0x00],
		[0x36, 0x00, 0x00, 0x00]
	];
	
	global.P = [
		[
		0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38, 0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82, 0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61, 0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7, 0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71, 0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90, 0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF, 0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A, 0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D, 0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4, 0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0],
		[
		0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B, 0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5, 0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51, 0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8, 0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2, 0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E, 0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9, 0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48, 0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64, 0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69, 0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC, 0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9, 0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91]
	];
	
}(this));

	
	/* Functions */
	
	function tohex(str) {
		return ("0" + str.toString(16)).slice(-2);
	}
	
	function bin2hex(str) {
		var res = [];
		var blank = '';
		var clen = str.length;
		var hexchars = '0123456789abcdef';
		var hex = new Array(clen * 2);
		for (var i = 0; i < clen; ++i) {
			hex[i * 2] = hexchars.charAt((str.charCodeAt(i) >> 4) & 15);
			hex[i * 2 + 1] = hexchars.charAt(str.charCodeAt(i) & 15);
		}
		return hex.join('');
	}
	
	function escCtrlChars(str) { // escape control chars which might cause problems handling ciphertext
		return str.replace(/[\0\v\f\xa0+!]/g, function (c) {
			return '!' + c.charCodeAt(0) + '!';
		});
	} // \xa0 to cater for bug in Firefox; include '+' to leave it free for use as a block marker
	
	function unescCtrlChars(str) { // unescape potentially problematic control characters
		return str.replace(/!\d\d?\d?!/g, function (c) {
			return String.fromCharCode(c.slice(1, -1));
		});
	}
	
	function byteArrayToHexStr(b) { // convert byte array to hex string for displaying test vectors
		var s = '';
		for (var i = 0; i < b.length; i++) s += b[i].toString(16) + ' ';
		return s;
	}
	
	function generate_pass(cipher, m, bytesource) {
	
		var bytesource = 'mozillaprng';
		var pass = '';
		var multi = true;
	
		if (!cipher) cipher = 10;
	
		switch (m) {
	
		default:
			chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
			break;
		case '0':
			chars = "1234506789";
			break;
		case '1':
			chars = "~!@#$%^&*()_+=-`|}{\][:';?.,<>0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
			break;
		case '2':
			chars = "0123456789abcdef";
			break;
		case '3':
			chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
			break;
		case '4':
			chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
			break;
		case '5':
			var multi = false;
			var buffer = '';
			var PRNG = Components.classes['@mozilla.org/security/random-generator;1'];
			var rg = PRNG.getService(Components.interfaces.nsIRandomGenerator);
			pass = rg.generateRandomBytes(cipher, buffer);
			break;
		}
		if (multi) {
			for (x = 0; x < cipher; x++) {
				rand = Math.random() * chars.length;
				genn = Math.round(rand);
				while (genn <= 0) {
					genn++;
				}
				pass += chars.charAt(genn);
			}
		}
		return pass;
	}
	
	function hashstring(str, method, id) {
	
		var converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"].createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
		// XXX: bugfix, for i18n we first need to set the charset to UTF-8.
		converter.charset = "UTF-8";
		var nocrc = true;
		var result = {};
		var data = converter.convertToByteArray(str, result);
		var hash_engine = Components.classes["@mozilla.org/security/hash;1"].createInstance().QueryInterface(Components.interfaces.nsICryptoHash);
	
		switch (method) {
		case 'MD2':
			hash_engine.init(hash_engine.MD2);
			break;
		case 'MD5':
			hash_engine.init(hash_engine.MD5);
			break;
		case 'SHA1':
			hash_engine.init(hash_engine.SHA1);
			break;
		case 'SHA256':
			hash_engine.init(hash_engine.SHA256);
			break;
		case 'SHA384':
			hash_engine.init(hash_engine.SHA384);
			break;
		case 'SHA512':
			hash_engine.init(hash_engine.SHA512);
			break;
		case 'CKSUM':
			nocrc = false;
			break;
		}
		hash_engine.update(data, result.value);
		document.getElementById(id).value = bin2hex(hash_engine.finish(false));
	}
	
	function hasher(path) {
	
		method = document.getElementById('hashact').value;
		var f = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsILocalFile);
		f.initWithPath(path);
		var istream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance(Components.interfaces.nsIFileInputStream);
		istream.init(f, 0x01, 0444, 0);
		var ch1 = Components.classes["@mozilla.org/security/hash;1"].createInstance(Components.interfaces.nsICryptoHash);
		var nocrc = true;
	
		switch (method) {
		case 'MD2':
			ch1.init(ch1.MD2);
			break;
		case 'MD5':
			ch1.init(ch1.MD5);
			break;
		case 'SHA1':
			ch1.init(ch1.SHA1);
			break;
		case 'SHA256':
			ch1.init(ch1.SHA256);
			break;
		case 'SHA384':
			ch1.init(ch1.SHA384);
			break;
		case 'SHA512':
			ch1.init(ch1.SHA512);
			break;
		}
	
		ch1.updateFromStream(istream, PR_UINT32_MAX);
		var hash1 = ch1.finish(false);
		return [tohex(hash1.charCodeAt(i)) for (i in hash1)].join("");
		istream.close();
	}
	
	function computehash() {
		const nsIFilePicker = Components.interfaces.nsIFilePicker;
		var fp = Components.classes["@mozilla.org/filepicker;1"].createInstance(nsIFilePicker);
		fp.init(window, "Browse file to compute checksum", nsIFilePicker.modeOpen);
		fp.appendFilters(nsIFilePicker.filterAll | nsIFilePicker.filterText);
		var rv = fp.show();
		if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace) {
			var file = fp.file;
			var path = fp.file.path;
			document.getElementById('checksumresult').value = hasher(path);
		}
	}
	
	// Yes! crypto is fugly! :o)
	/* AES */
	
	function Cipher(input, key, w) {
		var Nk = key.length / 4 // key length (in words)
		var Nr = Nk + 6;
		var Nb = 4;
	
		var state = [
			[],
			[],
			[],
			[]
		];
		for (var i = 0; i < 4 * Nb; i++) state[i % 4][Math.floor(i / 4)] = input[i];
	
		state = AddRoundKey(state, w, 0, Nb);
	
		for (var round = 1; round < Nr; round++) {
			state = SubBytes(state, Nb);
			state = ShiftRows(state, Nb);
			state = MixColumns(state, Nb);
			state = AddRoundKey(state, w, round, Nb);
		}
	
		state = SubBytes(state, Nb);
		state = ShiftRows(state, Nb);
		state = AddRoundKey(state, w, Nr, Nb);
	
		var output = new Array(4 * Nb);
		for (var i = 0; i < 4 * Nb; i++) output[i] = state[i % 4][Math.floor(i / 4)];
		return output;
	}
	
	function SubBytes(s, Nb) { // apply SBox to state S [§5.1.1]
		for (var r = 0; r < 4; r++) {
			for (var c = 0; c < Nb; c++) s[r][c] = Sbox[s[r][c]];
		}
		return s;
	}
	
	function ShiftRows(s, Nb) {
		var t = new Array(4);
		for (var r = 1; r < 4; r++) {
			for (var c = 0; c < 4; c++) t[c] = s[r][(c + r) % Nb];
			for (var c = 0; c < 4; c++) s[r][c] = t[c];
		}
		return s;
	}
	
	function MixColumns(s, Nb) {
		for (var c = 0; c < 4; c++) {
			var a = new Array(4);
			var b = new Array(4);
			for (var i = 0; i < 4; i++) {
				a[i] = s[i][c];
				b[i] = s[i][c] & 0x80 ? s[i][c] << 1 ^ 0x011b : s[i][c] << 1;
			}
			s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
			s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
			s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
			s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
		}
		return s;
	}
	
	function AddRoundKey(state, w, rnd, Nb) {
		for (var r = 0; r < 4; r++) {
			for (var c = 0; c < Nb; c++) state[r][c] ^= w[rnd * 4 + c][r];
		}
		return state;
	}
	
	function KeyExpansion(key) {
		var Nk = key.length / 4;
		var Nr = Nk + 6;
		var Nb = 4;
	
		var w = new Array(Nb * (Nr + 1));
		var temp = new Array(4);
	
		for (var i = 0; i < Nk; i++) {
			var r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
			w[i] = r;
		}
	
		for (var i = Nk; i < (Nb * (Nr + 1)); i++) {
			w[i] = new Array(4);
			for (var t = 0; t < 4; t++) temp[t] = w[i - 1][t];
			if (i % Nk == 0) {
				temp = SubWord(RotWord(temp));
				for (var t = 0; t < 4; t++) temp[t] ^= Rcon[i / Nk][t];
			} else if (Nk > 6 && i % Nk == 4) {
				temp = SubWord(temp);
			}
			for (var t = 0; t < 4; t++) w[i][t] = w[i - Nk][t] ^ temp[t];
		}
		return w;
	}
	
	function SubWord(w) {
		for (var i = 0; i < 4; i++) w[i] = Sbox[w[i]];
		return w;
	}
	
	function RotWord(w) {
		w[4] = w[0];
		for (var i = 0; i < 4; i++) w[i] = w[i + 1];
		return w;
	}
	
	function AESEncryptCtr128(plaintext, password) {
	
		plaintext = escape(plaintext).replace(/%20/g, ' ');
	
		var pwBytes = new Array(16);
		for (var i = 0; i < 16; i++) pwBytes[i] = password.charCodeAt(i);
		var pwKeySchedule = KeyExpansion([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]);
		var key = Cipher(pwBytes, pwBytes, pwKeySchedule);
	
		// initialise counter block (NIST SP800-38A §B.2)
		var counterBlock = new Array(16);
		var nonce = (new Date()).getTime();
		for (var i = 0; i < 8; i++) counterBlock[i] = (nonce >>> i * 8) & 0xff;
	
		var keySchedule = KeyExpansion(key);
	
		var blockCount = Math.ceil(plaintext.length / 16);
		var ciphertext = new Array(blockCount);
	
		for (var b = 0; b < blockCount; b++) {
			for (var c = 0; c < 8; c++) counterBlock[15 - c] = (b >>> c * 8) & 0xff;
	
			var cipherCntr = Cipher(counterBlock, key, keySchedule);
			var blockLength = b < blockCount - 1 ? 16 : (plaintext.length - 1) % 16 + 1;
	
			var ct = '';
			for (var i = 0; i < blockLength; i++) {
				var plaintextByte = plaintext.charCodeAt(b * 16 + i);
				var cipherByte = plaintextByte ^ cipherCntr[i];
				ct += String.fromCharCode(cipherByte);
			}
			ciphertext[b] = escCtrlChars(ct);
		}
	
		var ctrTxt = '';
		for (var i = 0; i < 4; i++) ctrTxt += String.fromCharCode(counterBlock[i]);
		ctrTxt = escCtrlChars(ctrTxt);
		return ctrTxt + '+' + ciphertext.join('+');
	}
	
	function AESDecryptCtr128(ciphertext, password) {
	
		var pwBytes = new Array(16);
		for (var i = 0; i < 16; i++) pwBytes[i] = password.charCodeAt(i);
		var pwKeySchedule = KeyExpansion([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]);
		var key = Cipher(pwBytes, pwBytes, pwKeySchedule);
	
		var keySchedule = KeyExpansion(key);
		ciphertext = ciphertext.split('+');
		var counterBlock = new Array(16);
		var ctrTxt = unescCtrlChars(ciphertext[0]);
		for (var i = 0; i < 8; i++) counterBlock[i] = ctrTxt.charCodeAt(i % 4);
	
		var plaintext = new Array(ciphertext.length - 1);
	
		for (var b = 1; b < ciphertext.length; b++) {
			for (var c = 0; c < 8; c++) counterBlock[15 - c] = ((b - 1) >>> c * 8) & 0xff;
	
			var cipherCntr = Cipher(counterBlock, key, keySchedule);
	
			ciphertext[b] = unescCtrlChars(ciphertext[b]);
	
			var pt = '';
			for (var i = 0; i < ciphertext[b].length; i++) {
				var ciphertextByte = ciphertext[b].charCodeAt(i);
				var plaintextByte = ciphertextByte ^ cipherCntr[i];
				pt += String.fromCharCode(plaintextByte);
			}
	
			plaintext[b] = pt;
		}
	
		return unescape(plaintext.join(''));
	}
	
	/* XOR encoder */
	
	function xorencode(Gkey1, Gkey2) {
		var results = "";
		var encode = Gkey1
		var xor_key = Gkey2
		for (v = 0; v < encode.length; ++v) {
			results += String.fromCharCode(xor_key ^ encode.charCodeAt(v));
		}
		var elem = document.getElementById('XorEncoded');
		elem.setAttribute('value', results);
	}
	
	function xordecode(Gkey1, Gkey2) {
		var results = "";
		var decode = Gkey1;
		var xor_key = Gkey2;
		for (d = 0; d < decode.length; d++) {
			var ddback = results += String.fromCharCode(xor_key ^ decode.charCodeAt(d));
			var elem = document.getElementById('XorDecoded');
			elem.setAttribute('value', ddback);
		}
	}
	
	function OneTimePad(encdec, text, key) {
		var pad, i, out, c, uc;
		pad = "";
		key = key.toUpperCase();
		for (i = 0; i < key.length; i++) {
			c = key.charAt(i)
			if (c >= 'A' && c <= 'Z') {
				pad += c;
			}
		}
		out = "";
		for (i = 0; i < text.length; i++) {
			c = text.charAt(i);
			uc = ' ';
			if (c >= 'A' && c <= 'Z') {
				uc = 'A';
			}
			if (c >= 'a' && c <= 'z') {
				uc = 'a';
			}
			if (uc != ' ') {
				if (pad.length == 0) {
					pad = "AAAAAAAA";
				}
				c = c.charCodeAt(0) - uc.charCodeAt(0) + encdec * (pad.charCodeAt(0) - 'A'.charCodeAt(0));
				c = (c + 26) % 26;
				c = String.fromCharCode(uc.charCodeAt(0) + c);
				pad = pad.slice(1, pad.length);
			}
			out += c;
		}
		if (encdec == 1) {
			var elem = document.getElementById('OTPE');
			elem.setAttribute('value', out);
		} else {
			var elem = document.getElementById('OTPD');
			elem.setAttribute('value', out);
		}
	}
	
	/* Rail Fence */
	
	function RFEncrypt(plaintext, depth, offset) {
		var plaintext, ciphertext, depth, offset, xs
		plaintext = plaintext.toUpperCase().replace(/\W/g, "")
		ciphertext = ""
		n = 2 * (depth) - 2
		if (offset > 0) {
			offset = offset % n
		}
		if (offset < 0) {
			offset = (offset % n) + n
		}
		xs = ""
		for (i = 1; i <= offset; i++) {
			xs = xs + "x"
		}
		plaintext = xs + plaintext
	
		for (d = 0; d <= n / 2; d++) {
			for (j = 0; j < plaintext.length; j++) {
				if (j % n == d || j % n == n - d) {
					ciphertext = ciphertext + plaintext.charAt(j)
				}
			}
		}
		ciphertext = ciphertext.replace(/x/g, "")
		var elem = document.getElementById('RFE');
		elem.setAttribute('value', ciphertext);
	}
	
	function RFDecrypt(ciphertext, depth, offset) {
		var plaintext, ciphertext, depth, offset, blocklen, increment, a, off, xs
		ciphertext = ciphertext.toLowerCase().replace(/\W/g, "")
		plaintext = ""
		n = 2 * (depth) - 2
		offset = offset % n
		if (offset < 0) {
			offset = offset + n
		}
		k = ciphertext.length + offset
		off = new Array()
		off[0] = Math.ceil(offset / n)
		for (i = 1; i < n / 2; i++) {
			off[i] = Math.ceil((offset - i) / n) + Math.floor((offset + i - 1) / n)
		}
		off[n / 2] = Math.ceil((offset - n / 2) / n)
	
		xs = new Array()
		for (i = 0; i <= n / 2; i++) {
			if (off[i] == 0) {
				xs[i] = ""
			}
			if (off[i] == 1) {
				xs[i] = "X"
			}
			if (off[i] == 2) {
				xs[i] = "XX"
			}
		}
	
		a = new Array()
		ciphertext = xs[0] + ciphertext
		a[0] = ciphertext.slice(0, Math.ceil(k / n)).split("")
		ciphertext = xs[1] + ciphertext.slice(Math.ceil(k / n))
		for (i = 1; i < n / 2; i++) {
			blocklen = Math.ceil((k - i) / n) + Math.floor((k + i - 1) / n)
			a[i] = ciphertext.slice(0, blocklen).split("")
			ciphertext = xs[i + 1] + ciphertext.slice(blocklen)
		}
		a[n / 2] = ciphertext.split("")
	
		i = 0
		while (a[i].length > 0) {
			plaintext = plaintext + a[i].shift()
			if (i == 0) {
				increment = 1
			}
			if (i == n / 2) {
				increment = -1
			}
			i = i + increment
		}
		plaintext = plaintext.replace(/X/g, "")
		var elem = document.getElementById('RFD');
		elem.setAttribute('value', plaintext);
	}
	
	/* Vigenere Cipher */
	
	function Vigenere(key, input, method) {
		var word, newword, code, newcode, newletter, key, keycode, input
		var method = method
		input = input.toUpperCase().replace(/\W/g, "")
		key = key.toUpperCase().replace(/\W/g, "")
		VigenereResult = ""
		if (method == 1) {
			for (n = 0; n < input.length; n++) {
				code = input.charCodeAt(n) - 65
				keycode = key.charCodeAt(n % key.length) - 65
				newcode = ((code + keycode) % 26) + 65
				newletter = String.fromCharCode(newcode)
				VigenereResult = VigenereResult + newletter
			}
		}
		if (method == 2) {
			for (n = 0; n < input.length; n++) {
				code = input.charCodeAt(n) - 65
				keycode = key.charCodeAt(n % key.length) - 65
				newcode = ((code - keycode + 26) % 26) + 65
				newletter = String.fromCharCode(newcode)
				PreLocal = VigenereResult + newletter
				VigenereResult = PreLocal.toLowerCase();
			}
		}
		return VigenereResult;
	}
	
	/* Affine Cipher */
	
	function AffineEncrypt(p, mult, add) {
		var p, newword, code, newcode, newletter, mult
		var addkey, multkey
		p = p.toUpperCase().replace(/\W/g, "")
		addkey = 0
		for (i = 0; i < add.length; i++) {
			addkey = addkey + (add) * (add)
		}
		multkey = 0
		for (i = 0; i < mult.length; i++) {
			multkey = multkey + (mult) * (mult)
		}
		newword = ""
		for (i = 0; i < p.length; i++) {
			code = p.charCodeAt(i) - 65
			newcode = ((multkey * code + addkey) % 26) + 65
			newletter = String.fromCharCode(newcode)
			newword = newword + newletter
		}
		result = newword + " "
		var elem = document.getElementById('AffineEncrypted');
		elem.setAttribute('value', result);
	}
	
	function AffineDecrypt(c, mult, add) {
		var c, newword, code, newcode, newletter, mult
		var addkey, multkey, multinverse
		c = c.toUpperCase().replace(/\W/g, "")
		addkey = 0
		for (i = 0; i < add.length; i++) {
			addkey = addkey + (add) * (add)
		}
		multkey = 0
		for (i = 0; i < mult.length; i++) {
			multkey = multkey + (mult) * (mult)
		}
		multinverse = 1
		for (i = 1; i <= 25; i = i + 2) {
			if ((multkey * i) % 26 == 1) {
				multinverse = i
			}
		}
		newword = ""
		for (i = 0; i < c.length; i++) {
			code = c.charCodeAt(i) - 65
			newcode = ((multinverse * (code + 26 - addkey)) % 26) + 65
			newletter = String.fromCharCode(newcode)
			newword = newword + newletter
		}
		result = newword.toLowerCase()
		var elem = document.getElementById('AffineDecrypted');
		elem.setAttribute('value', result);
	}
	
	/* Caesar Cipher Rot 13 */
	
	function rot(t, u, v) {
		return String.fromCharCode(((t - u + v) % (v * 2)) + u);
	}
	
	function Caesar(source) {
		var b = [],
			c, i = source.length,
			a = 'a'.charCodeAt(),
			z = a + 26,
			A = 'A'.charCodeAt(),
			Z = A + 26;
		while (i--) {
			c = source.charCodeAt(i);
			if (c >= a && c < z) {
				b[i] = rot(c, a, 13);
			} else if (c >= A && c < Z) {
				b[i] = rot(c, A, 13);
			} else {
				b[i] = source.charAt(i);
			}
		}
		output = b.join('');
		var elem = document.getElementById('CaesarOutput');
		elem.setAttribute('value', output);
	}
	
	function MDS_matrix() {
	
		m1 = new Array(2);
		mX = new Array(2);
		mY = new Array(2);
	
		var i, j;
	
		for (i = 0; i < 256; i++) {
			j = P[0][i] & 0xFF;
	
			m1[0] = j;
			mX[0] = Mx_X(j) & 0xFF;
			mY[0] = Mx_Y(j) & 0xFF;
	
			j = P[1][i] & 0xFF;
	
			m1[1] = j;
			mX[1] = Mx_X(j) & 0xFF;
			mY[1] = Mx_Y(j) & 0xFF;
	
	
			MDS[0 * 256 + i] = m1[P_00] << 0 | mX[P_00] << 8 | mY[P_00] << 16 | mY[P_00] << 24;
			MDS[1 * 256 + i] = mY[P_10] << 0 | mY[P_10] << 8 | mX[P_10] << 16 | m1[P_10] << 24;
			MDS[2 * 256 + i] = mX[P_20] << 0 | mY[P_20] << 8 | m1[P_20] << 16 | mY[P_20] << 24;
			MDS[3 * 256 + i] = mX[P_30] << 0 | m1[P_30] << 8 | mY[P_30] << 16 | mX[P_30] << 24;
		}
	}
	
	function LFSR1(x) {
		return (x >> 1) ^ ((x & 0x01) != 0 ? GF256_FDBK_2 : 0);
	}
	
	function LFSR2(x) {
		return (x >> 2) ^ ((x & 0x02) != 0 ? GF256_FDBK_2 : 0) ^ ((x & 0x01) != 0 ? GF256_FDBK_4 : 0);
	}
	
	function Mx_1(x) {
		return x;
	}
	
	function Mx_X(x) {
		return x ^ LFSR2(x);
	} // 5B
	
	
	function Mx_Y(x) {
		return x ^ LFSR1(x) ^ LFSR2(x);
	} // EF
	
	function makeKey(k) {
	
		var length = k.length;
		var k64Cnt = length >>> 3;
		var subkeyCnt = ROUND_SUBKEYS + 2 * ROUNDS;
	
		k32e = new Array(4);
		k32o = new Array(4);
		sBoxKey = new Array(4);
	
		var i, j, offset = 0;
		for (i = 0, j = k64Cnt - 1; i < 4 && offset < length; i++, j--) {
			k32e[i] = (k[offset++] & 0xFF) | (k[offset++] & 0xFF) << 8 | (k[offset++] & 0xFF) << 16 | (k[offset++] & 0xFF) << 24;
			k32o[i] = (k[offset++] & 0xFF) | (k[offset++] & 0xFF) << 8 | (k[offset++] & 0xFF) << 16 | (k[offset++] & 0xFF) << 24;
	
			sBoxKey[j] = RS_MDS_Encode(k32e[i], k32o[i]);
		}
	
		var q, A, B;
		subKeys = new Array(subkeyCnt);
		for (i = q = 0; i < subkeyCnt / 2; i++, q += SK_STEP) {
			A = F32(k64Cnt, q, k32e);
			B = F32(k64Cnt, q + SK_BUMP, k32o);
			B = B << 8 | B >>> 24;
			A += B;
			subKeys[2 * i] = A;
			A += B;
			subKeys[2 * i + 1] = A << SK_ROTL | A >>> (32 - SK_ROTL);
		}
	
		var k0 = sBoxKey[0];
		var k1 = sBoxKey[1];
		var k2 = sBoxKey[2];
		var k3 = sBoxKey[3];
		var b0, b1, b2, b3;
		sBox = new Array(4 * 256);
		for (i = 0; i < 256; i++) {
			b0 = b1 = b2 = b3 = i;
			switch (k64Cnt & 3) {
			case 1:
				sBox[2 * i] = MDS[0 * 256 + (P[P_01][b0] & 0xFF) ^ b_0(k0)];
				sBox[2 * i + 1] = MDS[1 * 256 + (P[P_11][b1] & 0xFF) ^ b_1(k0)];
				sBox[0x200 + 2 * i] = MDS[2 * 256 + (P[P_21][b2] & 0xFF) ^ b_2(k0)];
				sBox[0x200 + 2 * i + 1] = MDS[3 * 256 + (P[P_31][b3] & 0xFF) ^ b_3(k0)];
				break;
			case 0:
				b0 = (P[P_04][b0] & 0xFF) ^ b_0(k3);
				b1 = (P[P_14][b1] & 0xFF) ^ b_1(k3);
				b2 = (P[P_24][b2] & 0xFF) ^ b_2(k3);
				b3 = (P[P_34][b3] & 0xFF) ^ b_3(k3);
			case 3:
				b0 = (P[P_03][b0] & 0xFF) ^ b_0(k2);
				b1 = (P[P_13][b1] & 0xFF) ^ b_1(k2);
				b2 = (P[P_23][b2] & 0xFF) ^ b_2(k2);
				b3 = (P[P_33][b3] & 0xFF) ^ b_3(k2);
			case 2:
				sBox[2 * i] = MDS[0 * 256 + (P[P_01][(P[P_02][b0] & 0xFF) ^ b_0(k1)] & 0xFF) ^ b_0(k0)];
				sBox[2 * i + 1] = MDS[1 * 256 + (P[P_11][(P[P_12][b1] & 0xFF) ^ b_1(k1)] & 0xFF) ^ b_1(k0)];
				sBox[0x200 + 2 * i] = MDS[2 * 256 + (P[P_21][(P[P_22][b2] & 0xFF) ^ b_2(k1)] & 0xFF) ^ b_2(k0)];
				sBox[0x200 + 2 * i + 1] = MDS[3 * 256 + (P[P_31][(P[P_32][b3] & 0xFF) ^ b_3(k1)] & 0xFF) ^ b_3(k0)];
			}
		}
	
		sessionKey = new sessKey(sBox, subKeys);
		return sessionKey;
	}
	
	function sessKey(sBox, subKeys) {
		this.sBox = sBox;
		this.subKeys = subKeys;
	}
	
	function blockEncrypt(input, inOffset, sessionKey) {
	
		sk = sessionKey; // extract S-box and session key
		sBox = sk.sBox;
		sKey = sk.subKeys;
	
		var x0 = (input[inOffset++] & 0xFF) | (input[inOffset++] & 0xFF) << 8 | (input[inOffset++] & 0xFF) << 16 | (input[inOffset++] & 0xFF) << 24;
		var x1 = (input[inOffset++] & 0xFF) | (input[inOffset++] & 0xFF) << 8 | (input[inOffset++] & 0xFF) << 16 | (input[inOffset++] & 0xFF) << 24;
		var x2 = (input[inOffset++] & 0xFF) | (input[inOffset++] & 0xFF) << 8 | (input[inOffset++] & 0xFF) << 16 | (input[inOffset++] & 0xFF) << 24;
		var x3 = (input[inOffset++] & 0xFF) | (input[inOffset++] & 0xFF) << 8 | (input[inOffset++] & 0xFF) << 16 | (input[inOffset++] & 0xFF) << 24;
	
		x0 ^= sKey[INPUT_WHITEN];
		x1 ^= sKey[INPUT_WHITEN + 1];
		x2 ^= sKey[INPUT_WHITEN + 2];
		x3 ^= sKey[INPUT_WHITEN + 3];
	
		var t0, t1;
		var k = ROUND_SUBKEYS;
		for (var R = 0; R < ROUNDS; R += 2) {
			t0 = Fe32(sBox, x0, 0);
			t1 = Fe32(sBox, x1, 3);
			x2 ^= t0 + t1 + sKey[k++];
			x2 = x2 >>> 1 | x2 << 31;
			x3 = x3 << 1 | x3 >>> 31;
			x3 ^= t0 + 2 * t1 + sKey[k++];
	
			t0 = Fe32(sBox, x2, 0);
			t1 = Fe32(sBox, x3, 3);
			x0 ^= t0 + t1 + sKey[k++];
			x0 = x0 >>> 1 | x0 << 31;
			x1 = x1 << 1 | x1 >>> 31;
			x1 ^= t0 + 2 * t1 + sKey[k++];
	
			var R_1 = R + 1;
		}
	
		x2 ^= sKey[OUTPUT_WHITEN];
		x3 ^= sKey[OUTPUT_WHITEN + 1];
		x0 ^= sKey[OUTPUT_WHITEN + 2];
		x1 ^= sKey[OUTPUT_WHITEN + 3];
	
		var result = new Array();
	
		result[0] = x2 & 0xFF;
		result[1] = (x2 >>> 8) & 0xFF;
		result[2] = (x2 >>> 16) & 0xFF;
		result[3] = (x2 >>> 24) & 0xFF;
	
		result[4] = x3 & 0xFF;
		result[5] = (x3 >>> 8) & 0xFF;
		result[6] = (x3 >>> 16) & 0xFF;
		result[7] = (x3 >>> 24) & 0xFF;
	
		result[8] = x0 & 0xFF;
		result[9] = (x0 >>> 8) & 0xFF;
		result[10] = (x0 >>> 16) & 0xFF;
		result[11] = (x0 >>> 24) & 0xFF;
	
		result[12] = x1 & 0xFF;
		result[13] = (x1 >>> 8) & 0xFF;
		result[14] = (x1 >>> 16) & 0xFF;
		result[15] = (x1 >>> 24) & 0xFF;
	
		return result;
	}
	
	function blockDecrypt(input, inOffset, sessionKey) {
	
		sk = sessionKey;
		sBox = sk.sBox;
		sKey = sk.subKeys;
	
		var x2 = (input[inOffset++] & 0xFF) | (input[inOffset++] & 0xFF) << 8 | (input[inOffset++] & 0xFF) << 16 | (input[inOffset++] & 0xFF) << 24;
		var x3 = (input[inOffset++] & 0xFF) | (input[inOffset++] & 0xFF) << 8 | (input[inOffset++] & 0xFF) << 16 | (input[inOffset++] & 0xFF) << 24;
		var x0 = (input[inOffset++] & 0xFF) |
	
		(input[inOffset++] & 0xFF) << 8 | (input[inOffset++] & 0xFF) << 16 | (input[inOffset++] & 0xFF) << 24;
		var x1 = (input[inOffset++] & 0xFF) | (input[inOffset++] & 0xFF) << 8 | (input[inOffset++] & 0xFF) << 16 | (input[inOffset++] & 0xFF) << 24;
	
		x2 ^= sKey[OUTPUT_WHITEN];
		x3 ^= sKey[OUTPUT_WHITEN + 1];
		x0 ^= sKey[OUTPUT_WHITEN + 2];
		x1 ^= sKey[OUTPUT_WHITEN + 3];
	
	
		var k = ROUND_SUBKEYS + 2 * ROUNDS - 1;
		var t0, t1;
		for (var R = 0; R < ROUNDS; R += 2) {
			t0 = Fe32(sBox, x2, 0);
			t1 = Fe32(sBox, x3, 3);
			x1 ^= t0 + 2 * t1 + sKey[k--];
			x1 = x1 >>> 1 | x1 << 31;
			x0 = x0 << 1 | x0 >>> 31;
			x0 ^= t0 + t1 + sKey[k--];
	
			t0 = Fe32(sBox, x0, 0);
			t1 = Fe32(sBox, x1, 3);
			x3 ^= t0 + 2 * t1 + sKey[k--];
			x3 = x3 >>> 1 | x3 << 31;
			x2 = x2 << 1 | x2 >>> 31;
			x2 ^= t0 + t1 + sKey[k--];
	
		}
	
		x0 ^= sKey[INPUT_WHITEN];
		x1 ^= sKey[INPUT_WHITEN + 1];
		x2 ^= sKey[INPUT_WHITEN + 2];
		x3 ^= sKey[INPUT_WHITEN + 3];
	
		var result = new Array();
	
		result[0] = (x0) & 0xFF;
		result[1] = (x0 >>> 8) & 0xFF;
		result[2] = (x0 >>> 16) & 0xFF;
		result[3] = (x0 >>> 24) & 0xFF;
		result[4] = (x1) & 0xFF;
		result[5] = (x1 >>> 8) & 0xFF;
		result[6] = (x1 >>> 16) & 0xFF;
		result[7] = (x1 >>> 24) & 0xFF;
		result[8] = (x2) & 0xFF;
		result[9] = (x2 >>> 8) & 0xFF;
		result[10] = (x2 >>> 16) & 0xFF;
		result[11] = (x2 >>> 24) & 0xFF;
		result[12] = (x3) & 0xFF;
		result[13] = (x3 >>> 8) & 0xFF;
		result[14] = (x3 >>> 16) & 0xFF;
		result[15] = (x3 >>> 24) & 0xFF;
	
		return result;
	}
	
	function b_0(x) {
		return x & 0xFF;
	}
	
	function b_1(x) {
		return (x >>> 8) & 0xFF;
	}
	
	function b_2(x) {
		return (x >>> 16) & 0xFF;
	}
	
	function b_3(x) {
		return (x >>> 24) & 0xFF;
	}
	
	function RS_MDS_Encode(k0, k1) {
		var r = k1;
		for (var i = 0; i < 4; i++)
		r = RS_rem(r);
		r ^= k0;
		for (var i = 0; i < 4; i++)
		r = RS_rem(r);
		return r;
	}
	
	function RS_rem(x) {
		var b = (x >>> 24) & 0xFF;
		var g2 = ((b << 1) ^ ((b & 0x80) != 0 ? RS_GF_FDBK : 0)) & 0xFF;
		var g3 = (b >>> 1) ^ ((b & 0x01) != 0 ? (RS_GF_FDBK >>> 1) : 0) ^ g2;
		var result = (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;
		return result;
	}
	
	function F32(k64Cnt, x, k32) {
		var b0 = b_0(x);
		var b1 = b_1(x);
		var b2 = b_2(x);
		var b3 = b_3(x);
		var k0 = k32[0];
		var k1 = k32[1];
		var k2 = k32[2];
		var k3 = k32[3];
	
		var result = 0;
		switch (k64Cnt & 3) {
		case 1:
			result = MDS[0][(P[P_01][b0] & 0xFF) ^ b_0(k0)] ^ MDS[1][(P[P_11][b1] & 0xFF) ^ b_1(k0)] ^ MDS[2][(P[P_21][b2] & 0xFF) ^ b_2(k0)] ^ MDS[3][(P[P_31][b3] & 0xFF) ^ b_3(k0)];
			break;
		case 0:
			// same as 4
			b0 = (P[P_04][b0] & 0xFF) ^ b_0(k3);
			b1 = (P[P_14][b1] & 0xFF) ^ b_1(k3);
			b2 = (P[P_24][b2] & 0xFF) ^ b_2(k3);
			b3 = (P[P_34][b3] & 0xFF) ^ b_3(k3);
		case 3:
			b0 = (P[P_03][b0] & 0xFF) ^ b_0(k2);
			b1 = (P[P_13][b1] & 0xFF) ^ b_1(k2);
			b2 = (P[P_23][b2] & 0xFF) ^ b_2(k2);
			b3 = (P[P_33][b3] & 0xFF) ^ b_3(k2);
		case 2:
			result = MDS[0 * 256 + (P[P_01][(P[P_02][b0] & 0xFF) ^ b_0(k1)] & 0xFF) ^ b_0(k0)] ^ MDS[1 * 256 + (P[P_11][(P[P_12][b1] & 0xFF) ^ b_1(k1)] & 0xFF) ^ b_1(k0)] ^ MDS[2 * 256 + (P[P_21][(P[P_22][b2] & 0xFF) ^ b_2(k1)] & 0xFF) ^ b_2(k0)] ^ MDS[3 * 256 + (P[P_31][(P[P_32][b3] & 0xFF) ^ b_3(k1)] & 0xFF) ^ b_3(k0)];
			break;
		}
		return result;
	}
	
	function Fe32(sBox, x, R) {
		return sBox[2 * _b(x, R)] ^ sBox[2 * _b(x, R + 1) + 1] ^ sBox[0x200 + 2 * _b(x, R + 2)] ^ sBox[0x200 + 2 * _b(x, R + 3) + 1];
	}
	
	function _b(x, N) {
		var result = 0;
		switch (N % 4) {
		case 0:
			result = b_0(x);
			break;
		case 1:
			result = b_1(x);
			break;
		case 2:
			result = b_2(x);
			break;
		case 3:
			result = b_3(x);
			break;
		}
		return result;
	}
	
	/* Morse Function */
	
	function Morse(GetChars) {
		temp = '';
		blank = ' ';
		var CIM = new Array(42);
		CIM["1"] = ". _ _ _ _";
		CIM["2"] = ". . _ _ _";
		CIM["3"] = ". . . _ _";
		CIM["4"] = ". . . . _";
		CIM["5"] = ". . . . .";
		CIM["6"] = "_ . . . .";
		CIM["7"] = "_ _ . . .";
		CIM["8"] = "_ _ _ . .";
		CIM["9"] = "_ _ _ _ .";
		CIM["0"] = "_ _ _ _ _";
		CIM["a"] = ". _";
		CIM["b"] = "_ . . .";
		CIM["c"] = "_ . _ .";
		CIM["d"] = "_ . .";
		CIM["e"] = ".";
		CIM["f"] = ". . _ .";
		CIM["g"] = "_ _ .";
		CIM["h"] = ". . . .";
		CIM["i"] = ". .";
		CIM["j"] = ". _ _ _";
		CIM["k"] = "_ . _";
		CIM["l"] = ". _ . .";
		CIM["m"] = "_ _";
		CIM["n"] = "_ .";
		CIM["o"] = "_ _ _";
		CIM["p"] = ". _ _ .";
		CIM["q"] = "_ _ . _";
		CIM["r"] = ". _ .";
		CIM["s"] = ". . .";
		CIM["t"] = "_";
		CIM["u"] = ". . _";
		CIM["v"] = ". . . _";
		CIM["w"] = ". _ _";
		CIM["x"] = "_ . . _";
		CIM["y"] = "_ . _ _";
		CIM["z"] = "_ _ . .";
		CIM[" "] = " ";
		CIM["\n"] = " ";
		CIM["\r"] = " ";
		CIM["-"] = " ";
		CIM[":"] = " ";
		CIM["\r\n"] = " ";
		var temp = '';
		var PreChars = GetChars.toLowerCase().replace(/([.*+?^${}()|[\]\/\\])/g, ' ');
		var chars = PreChars.split("");
		for (var g = 0; g < chars.length; g++) {
			var elem = document.getElementById('MorseResult');
			elem.setAttribute('value', blank += CIM[chars[g]] + "  ");
			temp += chars[g] + "=" + CIM[chars[g]] + "\n";
		}
	}
	
	function generate_password(cijfer, where, m) {
		var elem = document.getElementById(where);
		elem.setAttribute('value', generate_pass(cijfer, m));
	}
	
	function showit() {
		var elem = document.getElementById('show');
		elem.setAttribute('value', passg);
	}
	
	function AESE(plaintext, password) {
		var elem = document.getElementById('a1');
		elem.setAttribute('value', AESEncryptCtr128(plaintext, password));
	}
	
	function AESD(plaintext, password) {
		var elem = document.getElementById('a2');
		elem.setAttribute('value', AESDecryptCtr128(plaintext, password));
	}
	
	function VigenereEncrypt(key, input) {
		var elem = document.getElementById('VigenereEncrypted');
		elem.setAttribute('value', Vigenere(key, input, "1"));
	}
	
	function VigenereDecrypt(key, input) {
		var elem = document.getElementById('VigenereDecrypted');
		elem.setAttribute('value', Vigenere(key, input, "2"));
	}
	
	function GG(Key1) {
		passX = Key1
	}
	
	function GetXor(Key2) {
		XorX = Key2
	}
	
	function GX(Key3) {
		passz = Key3
	}
	
	function CYX(Key4) {
		CY = Key4
	}
	
	function ShowKey(Key5) {
		NewKey = Key5
	}
	
	function SetDepth(Key6) {
		Depth = Key6
	}
	
	function SetOffset(Key7) {
		Offset = Key7
	}
	
	function KeyPad(Key8) {
		KeyPads = Key8
	}
	
	function Multiply(Key9) {
		MultiplyResult = Key9
	}
	
	function Add(Key10) {
		AddResult = Key10
	}
	
	function CountChars(Key11) {
		NumChars = Key11
	}
	
	function CheckMethod(Key12) {
		PassMethod = Key12
	}
	
	function TwofishKey(Key13) {
		TFKey = Key13
	}

/*$ EOF $*/
