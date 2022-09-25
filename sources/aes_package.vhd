-- aes_package.vhd
-- This package contains all operations required to perform key expansion,
-- key scheduling, and rounds in AES 256. The operations can be made to work
-- for any other AES key length by adjusting the paramaeters Nk and Nr
--Copyright (C) 2022  Austin Grieve
--
--    This program is free software: you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation, either version 3 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program.  If not, see <https://www.gnu.org/licenses/>.

library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.NUMERIC_STD.ALL;

package aes_package is

    -- cryptographic constants for AES-256
    constant Nk : integer := 8;
    constant Nb : integer := 4;
    constant Nr : integer := 14;

    -- these constants indicate the MSB positions of their respective vectors
    constant EXPANDED_WORDS_TOP : integer := Nb * (Nr + 1) - 1;
    constant KEY_TOP : integer := Nk * 32 - 1;
    constant BLOCK_TOP : integer := Nb * 32 - 1;
    -- hard-coded to 14 so that everything up to AES-256 works
    type t_RCON is array (0 to 14) of std_logic_vector(7 downto 0);
    constant RCON : t_RCON
        := (x"9a", x"01", x"02", x"04", x"08", x"10", x"20", x"40", x"80", 
            x"1b", x"36", x"6c", x"d8", x"ab", x"4d");

    -- type definitions
    type t_aes_expanded_key_word_array is array (0 to EXPANDED_WORDS_TOP)
        of std_logic_vector(31 downto 0);
    type aes_expanded_key_byte_array is array (0 to 
        (EXPANDED_WORDS_TOP + 1) * 4)
        of std_logic_vector(7 downto 0);
    type byte_vector is array (natural range <>) 
        of std_logic_vector(7 downto 0);

    -- functions

    -- during encryption, perform ShiftRows step
    -- i: state vector
    function shift_row_e (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector;

    -- during decryption, perform ShiftRows step
    -- i: state vector
    function shift_row_d (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector;

    -- adds the round key to the state vector
    -- a: state vector
    -- k: round key
    function add_round_key (
        a : std_logic_vector (BLOCK_TOP downto 0);
        k : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector;

    -- Rijndael S-box on one byte
    -- i: state vector
    function s_box (
        i : std_logic_vector (7 downto 0))
        return std_logic_vector;

    -- inverse S-box for decryption
    -- i: state vector
    function s_box_inv (
        i : std_logic_vector (7 downto 0))
        return std_logic_vector;

    -- MixColumn transformation during encryption
    -- i: state vector
    function mix_column_e (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector;

    -- MixColumn transformation during decryption
    -- i: state vector
    function mix_column_d (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector;

    -- performs multiplication over GF(2^8). vector b(x) is limited
    -- to four bits, as that is all that is ever used in AES
    -- b(x)=c(x) xor a(x), over GF(2^8), c(x) coprime to x^4 + 1
    -- b: four bit multiplicand vector
    -- a: 8 bit multiplicand vector
    -- output: 8 bit product vector
    function mult_gf (
        b : std_logic_vector (3 downto 0);
        a : std_logic_vector (7 downto 0))
        return std_logic_vector;

    -- 4-byte forward s-box operation. Used in key expansion
    -- w: word vector, whose 8-bit components are to be substituted
    function sub_word (
        w : std_logic_vector (31 downto 0))
        return std_logic_vector;

    -- Nb-word s-box operation. Used in each cipher round
    -- i: state vector
    function sub_block (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector;

    -- Nb-word inverse s-box operation. Used in each decryption cipher round
    -- i: state vector
    function sub_block_inv (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector;

    -- performs a byte-wise left shift on one word
    -- w: word vector to rotate
    function rot_word (
        w : std_logic_vector (31 downto 0))
        return std_logic_vector;

    -- expands the cipher key to produce the words necessary for all round
    -- keys. use with key scheduling
    -- key: cipher key vector
    -- output: array of each word to be used as round keys
    function key_expansion (
        key : std_logic_vector (KEY_TOP downto 0))
        return t_aes_expanded_key_word_array;

    -- fetch the key for a given round during encryption
    -- expanded_key: array of words from key expansion output
    -- round: round integer
    -- output: Nb-length round key
    function key_schedule_e (
        expanded_key : t_aes_expanded_key_word_array;
        round : integer)
        return std_logic_vector;

    -- fetch the key for a given round during decryption
    -- this function is the same as key_schedule_e with round set to Nr - round
    -- expanded_key: array of words from key expansion output
    -- round: round integer
    -- output: Nb-length round-key
    function key_schedule_d (
        expanded_key : t_aes_expanded_key_word_array;
        round : integer)
        return std_logic_vector;

    -- get the byte of a key by its byte number (big endian)
    -- vector: cipher key
    -- index: which word index to return (big endian)
    -- output: single byte from the index of the chosen key
    function get_key_byte (
        vector : std_logic_vector (KEY_TOP downto 0);
        index : integer)
        return std_logic_vector;

end package aes_package;

package body aes_package is

    function shift_row_e (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector is
    variable shifted : std_logic_vector (BLOCK_TOP downto 0);
    begin
        -- left shifts
        -- first row is unshifted, second by 1, third by 2, fourth by 3
        shifted :=
        i(127 downto 120) & i(87 downto 80) & i(47 downto 40) & i(7 downto 0) &
        i(95 downto 88) & i(55 downto 48) & i(15 downto 8) & i(103 downto 96) &
        i(63 downto 56) & i(23 downto 16) & i(111 downto 104) & i(71 downto 64)&
        i(31 downto 24) & i(119 downto 112) & i(79 downto 72) & i(39 downto 32);
        return shifted;
    end function shift_row_e;

    function shift_row_d (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector is
        variable shifted : std_logic_vector (BLOCK_TOP downto 0);
    begin
        -- right shifts
        -- first row is unshifted, second by 1, third by 2, fourth by 3
        shifted :=
        i(127 downto 120) & i(23 downto 16) & i(47 downto 40) & i(71 downto 64)&
        i(95 downto 88) & i(119 downto 112) & i(15 downto 8) & i(39 downto 32) &
        i(63 downto 56) & i(87 downto 80) & i(111 downto 104) & i(7 downto 0) &
        i(31 downto 24) & i(55 downto 48) & i(79 downto 72) & i(103 downto 96);
        return shifted;
    end function shift_row_d;

    function add_round_key (
        a : std_logic_vector (BLOCK_TOP downto 0);
        k : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector is
    begin

        return a xor k;

    end function add_round_key;

    function s_box (
        i : std_logic_vector (7 downto 0))
        return std_logic_vector is
        variable o : std_logic_vector (7 downto 0);
    begin
        case i is
            when x"00" => o := x"63";
            when x"01" => o := x"7c";
            when x"02" => o := x"77";
            when x"03" => o := x"7b";
            when x"04" => o := x"f2";
            when x"05" => o := x"6b";
            when x"06" => o := x"6f";
            when x"07" => o := x"c5";
            when x"08" => o := x"30";
            when x"09" => o := x"01";
            when x"0a" => o := x"67";
            when x"0b" => o := x"2b";
            when x"0c" => o := x"fe";
            when x"0d" => o := x"d7";
            when x"0e" => o := x"ab";
            when x"0f" => o := x"76";

            when x"10" => o := x"ca";
            when x"11" => o := x"82";
            when x"12" => o := x"c9";
            when x"13" => o := x"7d";
            when x"14" => o := x"fa";
            when x"15" => o := x"59";
            when x"16" => o := x"47";
            when x"17" => o := x"f0";
            when x"18" => o := x"ad";
            when x"19" => o := x"d4";
            when x"1a" => o := x"a2";
            when x"1b" => o := x"af";
            when x"1c" => o := x"9c";
            when x"1d" => o := x"a4";
            when x"1e" => o := x"72";
            when x"1f" => o := x"c0";

            when x"20" => o := x"b7";
            when x"21" => o := x"fd";
            when x"22" => o := x"93";
            when x"23" => o := x"26";
            when x"24" => o := x"36";
            when x"25" => o := x"3f";
            when x"26" => o := x"f7";
            when x"27" => o := x"cc";
            when x"28" => o := x"34";
            when x"29" => o := x"a5";
            when x"2a" => o := x"e5";
            when x"2b" => o := x"f1";
            when x"2c" => o := x"71";
            when x"2d" => o := x"d8";
            when x"2e" => o := x"31";
            when x"2f" => o := x"15";

            when x"30" => o := x"04";
            when x"31" => o := x"c7";
            when x"32" => o := x"23";
            when x"33" => o := x"c3";
            when x"34" => o := x"18";
            when x"35" => o := x"96";
            when x"36" => o := x"05";
            when x"37" => o := x"9a";
            when x"38" => o := x"07";
            when x"39" => o := x"12";
            when x"3a" => o := x"80";
            when x"3b" => o := x"e2";
            when x"3c" => o := x"eb";
            when x"3d" => o := x"27";
            when x"3e" => o := x"b2";
            when x"3f" => o := x"75";

            when x"40" => o := x"09";
            when x"41" => o := x"83";
            when x"42" => o := x"2c";
            when x"43" => o := x"1a";
            when x"44" => o := x"1b";
            when x"45" => o := x"6e";
            when x"46" => o := x"5a";
            when x"47" => o := x"a0";
            when x"48" => o := x"52";
            when x"49" => o := x"3b";
            when x"4a" => o := x"d6";
            when x"4b" => o := x"b3";
            when x"4c" => o := x"29";
            when x"4d" => o := x"e3";
            when x"4e" => o := x"2f";
            when x"4f" => o := x"84";

            when x"50" => o := x"53";
            when x"51" => o := x"d1";
            when x"52" => o := x"00";
            when x"53" => o := x"ed";
            when x"54" => o := x"20";
            when x"55" => o := x"fc";
            when x"56" => o := x"b1";
            when x"57" => o := x"5b";
            when x"58" => o := x"6a";
            when x"59" => o := x"cb";
            when x"5a" => o := x"be";
            when x"5b" => o := x"39";
            when x"5c" => o := x"4a";
            when x"5d" => o := x"4c";
            when x"5e" => o := x"58";
            when x"5f" => o := x"cf";

            when x"60" => o := x"d0";
            when x"61" => o := x"ef";
            when x"62" => o := x"aa";
            when x"63" => o := x"fb";
            when x"64" => o := x"43";
            when x"65" => o := x"4d";
            when x"66" => o := x"33";
            when x"67" => o := x"85";
            when x"68" => o := x"45";
            when x"69" => o := x"f9";
            when x"6a" => o := x"02";
            when x"6b" => o := x"7f";
            when x"6c" => o := x"50";
            when x"6d" => o := x"3c";
            when x"6e" => o := x"9f";
            when x"6f" => o := x"a8";

            when x"70" => o := x"51";
            when x"71" => o := x"a3";
            when x"72" => o := x"40";
            when x"73" => o := x"8f";
            when x"74" => o := x"92";
            when x"75" => o := x"9d";
            when x"76" => o := x"38";
            when x"77" => o := x"f5";
            when x"78" => o := x"bc";
            when x"79" => o := x"b6";
            when x"7a" => o := x"da";
            when x"7b" => o := x"21";
            when x"7c" => o := x"10";
            when x"7d" => o := x"ff";
            when x"7e" => o := x"f3";
            when x"7f" => o := x"d2";

            when x"80" => o := x"cd";
            when x"81" => o := x"0c";
            when x"82" => o := x"13";
            when x"83" => o := x"ec";
            when x"84" => o := x"5f";
            when x"85" => o := x"97";
            when x"86" => o := x"44";
            when x"87" => o := x"17";
            when x"88" => o := x"c4";
            when x"89" => o := x"a7";
            when x"8a" => o := x"7e";
            when x"8b" => o := x"3d";
            when x"8c" => o := x"64";
            when x"8d" => o := x"5d";
            when x"8e" => o := x"19";
            when x"8f" => o := x"73";

            when x"90" => o := x"60";
            when x"91" => o := x"81";
            when x"92" => o := x"4f";
            when x"93" => o := x"dc";
            when x"94" => o := x"22";
            when x"95" => o := x"2a";
            when x"96" => o := x"90";
            when x"97" => o := x"88";
            when x"98" => o := x"46";
            when x"99" => o := x"ee";
            when x"9a" => o := x"b8";
            when x"9b" => o := x"14";
            when x"9c" => o := x"de";
            when x"9d" => o := x"5e";
            when x"9e" => o := x"0b";
            when x"9f" => o := x"db";

            when x"a0" => o := x"e0";
            when x"a1" => o := x"32";
            when x"a2" => o := x"3a";
            when x"a3" => o := x"0a";
            when x"a4" => o := x"49";
            when x"a5" => o := x"06";
            when x"a6" => o := x"24";
            when x"a7" => o := x"5c";
            when x"a8" => o := x"c2";
            when x"a9" => o := x"d3";
            when x"aa" => o := x"ac";
            when x"ab" => o := x"62";
            when x"ac" => o := x"91";
            when x"ad" => o := x"95";
            when x"ae" => o := x"e4";
            when x"af" => o := x"79";

            when x"b0" => o := x"e7";
            when x"b1" => o := x"c8";
            when x"b2" => o := x"37";
            when x"b3" => o := x"6d";
            when x"b4" => o := x"8d";
            when x"b5" => o := x"d5";
            when x"b6" => o := x"4e";
            when x"b7" => o := x"a9";
            when x"b8" => o := x"6c";
            when x"b9" => o := x"56";
            when x"ba" => o := x"f4";
            when x"bb" => o := x"ea";
            when x"bc" => o := x"65";
            when x"bd" => o := x"7a";
            when x"be" => o := x"ae";
            when x"bf" => o := x"08";

            when x"c0" => o := x"ba";
            when x"c1" => o := x"78";
            when x"c2" => o := x"25";
            when x"c3" => o := x"2e";
            when x"c4" => o := x"1c";
            when x"c5" => o := x"a6";
            when x"c6" => o := x"b4";
            when x"c7" => o := x"c6";
            when x"c8" => o := x"e8";
            when x"c9" => o := x"dd";
            when x"ca" => o := x"74";
            when x"cb" => o := x"1f";
            when x"cc" => o := x"4b";
            when x"cd" => o := x"bd";
            when x"ce" => o := x"8b";
            when x"cf" => o := x"8a";

            when x"d0" => o := x"70";
            when x"d1" => o := x"3e";
            when x"d2" => o := x"b5";
            when x"d3" => o := x"66";
            when x"d4" => o := x"48";
            when x"d5" => o := x"03";
            when x"d6" => o := x"f6";
            when x"d7" => o := x"0e";
            when x"d8" => o := x"61";
            when x"d9" => o := x"35";
            when x"da" => o := x"57";
            when x"db" => o := x"b9";
            when x"dc" => o := x"86";
            when x"dd" => o := x"c1";
            when x"de" => o := x"1d";
            when x"df" => o := x"9e";

            when x"e0" => o := x"e1";
            when x"e1" => o := x"f8";
            when x"e2" => o := x"98";
            when x"e3" => o := x"11";
            when x"e4" => o := x"69";
            when x"e5" => o := x"d9";
            when x"e6" => o := x"8e";
            when x"e7" => o := x"94";
            when x"e8" => o := x"9b";
            when x"e9" => o := x"1e";
            when x"ea" => o := x"87";
            when x"eb" => o := x"e9";
            when x"ec" => o := x"ce";
            when x"ed" => o := x"55";
            when x"ee" => o := x"28";
            when x"ef" => o := x"df";

            when x"f0" => o := x"8c";
            when x"f1" => o := x"a1";
            when x"f2" => o := x"89";
            when x"f3" => o := x"0d";
            when x"f4" => o := x"bf";
            when x"f5" => o := x"e6";
            when x"f6" => o := x"42";
            when x"f7" => o := x"68";
            when x"f8" => o := x"41";
            when x"f9" => o := x"99";
            when x"fa" => o := x"2d";
            when x"fb" => o := x"0f";
            when x"fc" => o := x"b0";
            when x"fd" => o := x"54";
            when x"fe" => o := x"bb";
            when x"ff" => o := x"16";
            when others => o := x"00";
        end case;
        return o;
    end function s_box;

    function s_box_inv (
        i : std_logic_vector (7 downto 0))
        return std_logic_vector is
        variable o : std_logic_vector (7 downto 0);
    begin
        case i is
            when x"00" => o := x"52";
            when x"01" => o := x"09";
            when x"02" => o := x"6a";
            when x"03" => o := x"d5";
            when x"04" => o := x"30";
            when x"05" => o := x"36";
            when x"06" => o := x"a5";
            when x"07" => o := x"38";
            when x"08" => o := x"bf";
            when x"09" => o := x"40";
            when x"0a" => o := x"a3";
            when x"0b" => o := x"9e";
            when x"0c" => o := x"81";
            when x"0d" => o := x"f3";
            when x"0e" => o := x"d7";
            when x"0f" => o := x"fb";

            when x"10" => o := x"7c";
            when x"11" => o := x"e3";
            when x"12" => o := x"39";
            when x"13" => o := x"82";
            when x"14" => o := x"9b";
            when x"15" => o := x"2f";
            when x"16" => o := x"ff";
            when x"17" => o := x"87";
            when x"18" => o := x"34";
            when x"19" => o := x"8e";
            when x"1a" => o := x"43";
            when x"1b" => o := x"44";
            when x"1c" => o := x"c4";
            when x"1d" => o := x"de";
            when x"1e" => o := x"e9";
            when x"1f" => o := x"cb";

            when x"20" => o := x"54";
            when x"21" => o := x"7b";
            when x"22" => o := x"94";
            when x"23" => o := x"32";
            when x"24" => o := x"a6";
            when x"25" => o := x"c2";
            when x"26" => o := x"23";
            when x"27" => o := x"3d";
            when x"28" => o := x"ee";
            when x"29" => o := x"4c";
            when x"2a" => o := x"95";
            when x"2b" => o := x"0b";
            when x"2c" => o := x"42";
            when x"2d" => o := x"fa";
            when x"2e" => o := x"c3";
            when x"2f" => o := x"4e";

            when x"30" => o := x"08";
            when x"31" => o := x"2e";
            when x"32" => o := x"a1";
            when x"33" => o := x"66";
            when x"34" => o := x"28";
            when x"35" => o := x"d9";
            when x"36" => o := x"24";
            when x"37" => o := x"b2";
            when x"38" => o := x"76";
            when x"39" => o := x"5b";
            when x"3a" => o := x"a2";
            when x"3b" => o := x"49";
            when x"3c" => o := x"6d";
            when x"3d" => o := x"8b";
            when x"3e" => o := x"d1";
            when x"3f" => o := x"25";

            when x"40" => o := x"72";
            when x"41" => o := x"f8";
            when x"42" => o := x"f6";
            when x"43" => o := x"64";
            when x"44" => o := x"86";
            when x"45" => o := x"68";
            when x"46" => o := x"98";
            when x"47" => o := x"16";
            when x"48" => o := x"d4";
            when x"49" => o := x"a4";
            when x"4a" => o := x"5c";
            when x"4b" => o := x"cc";
            when x"4c" => o := x"5d";
            when x"4d" => o := x"65";
            when x"4e" => o := x"b6";
            when x"4f" => o := x"92";

            when x"50" => o := x"6c";
            when x"51" => o := x"70";
            when x"52" => o := x"48";
            when x"53" => o := x"50";
            when x"54" => o := x"fd";
            when x"55" => o := x"ed";
            when x"56" => o := x"b9";
            when x"57" => o := x"da";
            when x"58" => o := x"5e";
            when x"59" => o := x"15";
            when x"5a" => o := x"46";
            when x"5b" => o := x"57";
            when x"5c" => o := x"a7";
            when x"5d" => o := x"8d";
            when x"5e" => o := x"9d";
            when x"5f" => o := x"84";

            when x"60" => o := x"90";
            when x"61" => o := x"d8";
            when x"62" => o := x"ab";
            when x"63" => o := x"00";
            when x"64" => o := x"8c";
            when x"65" => o := x"bc";
            when x"66" => o := x"d3";
            when x"67" => o := x"0a";
            when x"68" => o := x"f7";
            when x"69" => o := x"e4";
            when x"6a" => o := x"58";
            when x"6b" => o := x"05";
            when x"6c" => o := x"b8";
            when x"6d" => o := x"b3";
            when x"6e" => o := x"45";
            when x"6f" => o := x"06";

            when x"70" => o := x"d0";
            when x"71" => o := x"2c";
            when x"72" => o := x"1e";
            when x"73" => o := x"8f";
            when x"74" => o := x"ca";
            when x"75" => o := x"3f";
            when x"76" => o := x"0f";
            when x"77" => o := x"02";
            when x"78" => o := x"c1";
            when x"79" => o := x"af";
            when x"7a" => o := x"bd";
            when x"7b" => o := x"03";
            when x"7c" => o := x"01";
            when x"7d" => o := x"13";
            when x"7e" => o := x"8a";
            when x"7f" => o := x"6b";

            when x"80" => o := x"3a";
            when x"81" => o := x"91";
            when x"82" => o := x"11";
            when x"83" => o := x"41";
            when x"84" => o := x"4f";
            when x"85" => o := x"67";
            when x"86" => o := x"dc";
            when x"87" => o := x"ea";
            when x"88" => o := x"97";
            when x"89" => o := x"f2";
            when x"8a" => o := x"cf";
            when x"8b" => o := x"ce";
            when x"8c" => o := x"f0";
            when x"8d" => o := x"b4";
            when x"8e" => o := x"e6";
            when x"8f" => o := x"73";

            when x"90" => o := x"96";
            when x"91" => o := x"ac";
            when x"92" => o := x"74";
            when x"93" => o := x"22";
            when x"94" => o := x"e7";
            when x"95" => o := x"ad";
            when x"96" => o := x"35";
            when x"97" => o := x"85";
            when x"98" => o := x"e2";
            when x"99" => o := x"f9";
            when x"9a" => o := x"37";
            when x"9b" => o := x"e8";
            when x"9c" => o := x"1c";
            when x"9d" => o := x"75";
            when x"9e" => o := x"df";
            when x"9f" => o := x"6e";

            when x"a0" => o := x"47";
            when x"a1" => o := x"f1";
            when x"a2" => o := x"1a";
            when x"a3" => o := x"71";
            when x"a4" => o := x"1d";
            when x"a5" => o := x"29";
            when x"a6" => o := x"c5";
            when x"a7" => o := x"89";
            when x"a8" => o := x"6f";
            when x"a9" => o := x"b7";
            when x"aa" => o := x"62";
            when x"ab" => o := x"0e";
            when x"ac" => o := x"aa";
            when x"ad" => o := x"18";
            when x"ae" => o := x"be";
            when x"af" => o := x"1b";

            when x"b0" => o := x"fc";
            when x"b1" => o := x"56";
            when x"b2" => o := x"3e";
            when x"b3" => o := x"4b";
            when x"b4" => o := x"c6";
            when x"b5" => o := x"d2";
            when x"b6" => o := x"79";
            when x"b7" => o := x"20";
            when x"b8" => o := x"9a";
            when x"b9" => o := x"db";
            when x"ba" => o := x"c0";
            when x"bb" => o := x"fe";
            when x"bc" => o := x"78";
            when x"bd" => o := x"cd";
            when x"be" => o := x"5a";
            when x"bf" => o := x"f4";

            when x"c0" => o := x"1f";
            when x"c1" => o := x"dd";
            when x"c2" => o := x"a8";
            when x"c3" => o := x"33";
            when x"c4" => o := x"88";
            when x"c5" => o := x"07";
            when x"c6" => o := x"c7";
            when x"c7" => o := x"31";
            when x"c8" => o := x"b1";
            when x"c9" => o := x"12";
            when x"ca" => o := x"10";
            when x"cb" => o := x"59";
            when x"cc" => o := x"27";
            when x"cd" => o := x"80";
            when x"ce" => o := x"ec";
            when x"cf" => o := x"5f";

            when x"d0" => o := x"60";
            when x"d1" => o := x"51";
            when x"d2" => o := x"7f";
            when x"d3" => o := x"a9";
            when x"d4" => o := x"19";
            when x"d5" => o := x"b5";
            when x"d6" => o := x"4a";
            when x"d7" => o := x"0d";
            when x"d8" => o := x"2d";
            when x"d9" => o := x"e5";
            when x"da" => o := x"7a";
            when x"db" => o := x"9f";
            when x"dc" => o := x"93";
            when x"dd" => o := x"c9";
            when x"de" => o := x"9c";
            when x"df" => o := x"ef";

            when x"e0" => o := x"a0";
            when x"e1" => o := x"e0";
            when x"e2" => o := x"3b";
            when x"e3" => o := x"4d";
            when x"e4" => o := x"ae";
            when x"e5" => o := x"2a";
            when x"e6" => o := x"f5";
            when x"e7" => o := x"b0";
            when x"e8" => o := x"c8";
            when x"e9" => o := x"eb";
            when x"ea" => o := x"bb";
            when x"eb" => o := x"3c";
            when x"ec" => o := x"83";
            when x"ed" => o := x"53";
            when x"ee" => o := x"99";
            when x"ef" => o := x"61";

            when x"f0" => o := x"17";
            when x"f1" => o := x"2b";
            when x"f2" => o := x"04";
            when x"f3" => o := x"7e";
            when x"f4" => o := x"ba";
            when x"f5" => o := x"77";
            when x"f6" => o := x"d6";
            when x"f7" => o := x"26";
            when x"f8" => o := x"e1";
            when x"f9" => o := x"69";
            when x"fa" => o := x"14";
            when x"fb" => o := x"63";
            when x"fc" => o := x"55";
            when x"fd" => o := x"21";
            when x"fe" => o := x"0c";
            when x"ff" => o := x"7d";
            when others => o := x"00";
        end case;
        return o;
    end function s_box_inv;

    function mix_column_e (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector is
        variable o : std_logic_vector(BLOCK_TOP downto 0);
    begin
        -- each o column => b(x), each i column => a(x)
        -- c(x) = 03x^3 + 01x^2 + 01x + 02 in GF(2^8)
        -- b(x) = a(x) xor c(x)
        o := -- b_0   127 downto 96
                (mult_gf(x"2", i(127 downto 120))
            xor mult_gf(x"3", i(119 downto 112))
            xor mult_gf(x"1", i(111 downto 104))
            xor mult_gf(x"1", i(103 downto  96))) &
                (mult_gf(x"1", i(127 downto 120))
            xor mult_gf(x"2", i(119 downto 112))
            xor mult_gf(x"3", i(111 downto 104))
            xor mult_gf(x"1", i(103 downto  96))) &
                (mult_gf(x"1", i(127 downto 120))
            xor mult_gf(x"1", i(119 downto 112))
            xor mult_gf(x"2", i(111 downto 104))
            xor mult_gf(x"3", i(103 downto  96))) &
                (mult_gf(x"3", i(127 downto 120))
            xor mult_gf(x"1", i(119 downto 112))
            xor mult_gf(x"1", i(111 downto 104))
            xor mult_gf(x"2", i(103 downto  96))) &
            --  b_1 95 downto 64
                (mult_gf(x"2", i(95 downto 88))
            xor mult_gf(x"3", i(87 downto 80))
            xor mult_gf(x"1", i(79 downto 72))
            xor mult_gf(x"1", i(71 downto 64))) &
                (mult_gf(x"1", i(95 downto 88))
            xor mult_gf(x"2", i(87 downto 80))
            xor mult_gf(x"3", i(79 downto 72))
            xor mult_gf(x"1", i(71 downto 64))) &
                (mult_gf(x"1", i(95 downto 88))
            xor mult_gf(x"1", i(87 downto 80))
            xor mult_gf(x"2", i(79 downto 72))
            xor mult_gf(x"3", i(71 downto 64))) &
                (mult_gf(x"3", i(95 downto 88))
            xor mult_gf(x"1", i(87 downto 80))
            xor mult_gf(x"1", i(79 downto 72))
            xor mult_gf(x"2", i(71 downto 64))) &
            --  b_2 63 downto 32
                (mult_gf(x"2", i(63 downto 56))
            xor mult_gf(x"3", i(55 downto 48))
            xor mult_gf(x"1", i(47 downto 40))
            xor mult_gf(x"1", i(39 downto 32))) &
                (mult_gf(x"1", i(63 downto 56))
            xor mult_gf(x"2", i(55 downto 48))
            xor mult_gf(x"3", i(47 downto 40))
            xor mult_gf(x"1", i(39 downto 32))) &
                (mult_gf(x"1", i(63 downto 56))
            xor mult_gf(x"1", i(55 downto 48))
            xor mult_gf(x"2", i(47 downto 40))
            xor mult_gf(x"3", i(39 downto 32))) &
                (mult_gf(x"3", i(63 downto 56))
            xor mult_gf(x"1", i(55 downto 48))
            xor mult_gf(x"1", i(47 downto 40))
            xor mult_gf(x"2", i(39 downto 32))) &
            --  b_3 31 downto 00
                (mult_gf(x"2", i(31 downto 24))
            xor mult_gf(x"3", i(23 downto 16))
            xor mult_gf(x"1", i(15 downto  8))
            xor mult_gf(x"1", i(7  downto  0))) &
                (mult_gf(x"1", i(31 downto 24))
            xor mult_gf(x"2", i(23 downto 16))
            xor mult_gf(x"3", i(15 downto  8))
            xor mult_gf(x"1", i(7  downto  0))) &
                (mult_gf(x"1", i(31 downto 24))
            xor mult_gf(x"1", i(23 downto 16))
            xor mult_gf(x"2", i(15 downto  8))
            xor mult_gf(x"3", i(7  downto  0))) &
                (mult_gf(x"3", i(31 downto 24))
            xor mult_gf(x"1", i(23 downto 16))
            xor mult_gf(x"1", i(15 downto  8))
            xor mult_gf(x"2", i(7  downto  0)));
        return o;
    end function mix_column_e;

    function mix_column_d (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector is
        variable o : std_logic_vector(BLOCK_TOP downto 0);
    begin
        -- each o column => b(x), each i column => a(x)
        -- d(x) = 0Bx^3 + 0Dx^2 + 09x + 0E in GF(2^8)
        -- b(x) = a(x) xor d(x)
        o := -- b_0   127 downto 96
            (mult_gf(x"e", i(127 downto 120))
            xor mult_gf(x"b", i(119 downto 112))
            xor mult_gf(x"d", i(111 downto 104))
            xor mult_gf(x"9", i(103 downto  96))) &
                (mult_gf(x"9", i(127 downto 120))
            xor mult_gf(x"e", i(119 downto 112))
            xor mult_gf(x"b", i(111 downto 104))
            xor mult_gf(x"d", i(103 downto  96))) &
                (mult_gf(x"d", i(127 downto 120))
            xor mult_gf(x"9", i(119 downto 112))
            xor mult_gf(x"e", i(111 downto 104))
            xor mult_gf(x"b", i(103 downto  96))) &
                (mult_gf(x"b", i(127 downto 120))
            xor mult_gf(x"d", i(119 downto 112))
            xor mult_gf(x"9", i(111 downto 104))
            xor mult_gf(x"e", i(103 downto  96))) &
            --  b_1 95 downto 64
                (mult_gf(x"e", i(95 downto 88))
            xor mult_gf(x"b", i(87 downto 80))
            xor mult_gf(x"d", i(79 downto 72))
            xor mult_gf(x"9", i(71 downto 64))) &
                (mult_gf(x"9", i(95 downto 88))
            xor mult_gf(x"e", i(87 downto 80))
            xor mult_gf(x"b", i(79 downto 72))
            xor mult_gf(x"d", i(71 downto 64))) &
                (mult_gf(x"d", i(95 downto 88))
            xor mult_gf(x"9", i(87 downto 80))
            xor mult_gf(x"e", i(79 downto 72))
            xor mult_gf(x"b", i(71 downto 64))) &
                (mult_gf(x"b", i(95 downto 88))
            xor mult_gf(x"d", i(87 downto 80))
            xor mult_gf(x"9", i(79 downto 72))
            xor mult_gf(x"e", i(71 downto 64))) &
            --  b_2 63 downto 32
                (mult_gf(x"e", i(63 downto 56))
            xor mult_gf(x"b", i(55 downto 48))
            xor mult_gf(x"d", i(47 downto 40))
            xor mult_gf(x"9", i(39 downto 32))) &
                (mult_gf(x"9", i(63 downto 56))
            xor mult_gf(x"e", i(55 downto 48))
            xor mult_gf(x"b", i(47 downto 40))
            xor mult_gf(x"d", i(39 downto 32))) &
                (mult_gf(x"d", i(63 downto 56))
            xor mult_gf(x"9", i(55 downto 48))
            xor mult_gf(x"e", i(47 downto 40))
            xor mult_gf(x"b", i(39 downto 32))) &
                (mult_gf(x"b", i(63 downto 56))
            xor mult_gf(x"d", i(55 downto 48))
            xor mult_gf(x"9", i(47 downto 40))
            xor mult_gf(x"e", i(39 downto 32))) &
            --  b_3 31 downto 00
                (mult_gf(x"e", i(31 downto 24))
            xor mult_gf(x"b", i(23 downto 16))
            xor mult_gf(x"d", i(15 downto  8))
            xor mult_gf(x"9", i(7  downto  0))) &
                (mult_gf(x"9", i(31 downto 24))
            xor mult_gf(x"e", i(23 downto 16))
            xor mult_gf(x"b", i(15 downto  8))
            xor mult_gf(x"d", i(7  downto  0))) &
                (mult_gf(x"d", i(31 downto 24))
            xor mult_gf(x"9", i(23 downto 16))
            xor mult_gf(x"e", i(15 downto  8))
            xor mult_gf(x"b", i(7  downto  0))) &
                (mult_gf(x"b", i(31 downto 24))
            xor mult_gf(x"d", i(23 downto 16))
            xor mult_gf(x"9", i(15 downto  8))
            xor mult_gf(x"e", i(7  downto  0)));
        return o;
    end function mix_column_d;

    function mult_gf (
        b : std_logic_vector (3 downto 0);
        a : std_logic_vector (7 downto 0))
        return std_logic_vector is
        variable t : std_logic_vector (10 downto 0);
        constant irreducible : std_logic_vector (8 downto 0) := "100011011";
    begin
        case b is
            when x"1" => 
                t := "000" & a;
            when x"2" => 
                t := "00" & a & "0";
            when x"3" => 
                t := ("00" & a & "0") xor ("000" & a);
            when x"9" => 
                t := (a & "000") xor ("000" & a);
            when x"b" => 
                t := (a & "000") xor ("00" & a & "0") xor ("000" & a);
            when x"d" => 
                t := (a & "000") xor ("0" & a & "00") xor ("000" & a);
            when x"e" => 
                t := (a & "000") xor ("0" & a & "00") xor ("00" & a & "0");
            when others => t := "00000000000"; -- others not used in AES
        end case;

        -- perform modulo operation with GF(2^8) irreducible
        if t(10) = '1' then
            t := t xor (irreducible & "00");
        end if;
        if t(9) = '1' then
            t := t xor ("0" & irreducible & "0");
        end if;
        if t(8) = '1' then
            t := t xor ("00" & irreducible);
        end if;

        return t(7 downto 0);

    end function mult_gf;

    function sub_word (
        w : std_logic_vector (31 downto 0))
        return std_logic_vector is
    begin
        return s_box(w(31 downto 24)) & s_box(w(23 downto 16)) 
            & s_box(w(15 downto 8)) & s_box(w(7 downto 0));
    end function sub_word;

    function sub_word_inv (
        w : std_logic_vector (31 downto 0))
        return std_logic_vector is
    begin
        return s_box_inv(w(31 downto 24)) & s_box_inv(w(23 downto 16)) 
            & s_box_inv(w(15 downto 8)) & s_box_inv(w(7 downto 0));
    end function sub_word_inv;

    function sub_block (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector is
    begin
        return sub_word(i(127 downto 96)) & sub_word(i(95 downto 64))
            & sub_word(i(63 downto 32)) & sub_word(i(31 downto 0));
    end function sub_block;

    function sub_block_inv (
        i : std_logic_vector (BLOCK_TOP downto 0))
        return std_logic_vector is
    begin
        return sub_word_inv(i(127 downto 96)) & sub_word_inv(i(95 downto 64))
            & sub_word_inv(i(63 downto 32)) & sub_word_inv(i(31 downto 0));
    end function sub_block_inv;

    function rot_word (
        w : std_logic_vector (31 downto 0))
        return std_logic_vector is
    begin
        return w(23 downto 0) & w(31 downto 24);
    end function rot_word;

    function key_expansion (
        key : std_logic_vector (KEY_TOP downto 0))
        return t_aes_expanded_key_word_array is
        variable temp : std_logic_vector (31 downto 0);
        variable w : t_aes_expanded_key_word_array;
    begin
        -- first loop to initialize word array at index i
        for i in 0 to Nk - 1 loop
            w(i) := get_key_byte(key, 4 * i) & get_key_byte(key, 4 * i + 1)
                & get_key_byte(key, 4 * i + 2) & get_key_byte(key, 4 * i + 3);
        end loop;

        -- perform substitution and rotation for each word
        for i in Nk to EXPANDED_WORDS_TOP loop
            temp := w(i - 1);
            if i mod Nk = 0 then
                temp := sub_word(rot_word(temp)) xor RCON(i / Nk) & x"000000";
            elsif (Nk > 6) and (i mod Nk = 4) then
                temp := sub_word(temp);
            else -- to have a complete if
                temp := temp;
            end if;

            w(i) := w(i - Nk) xor temp;
        end loop;

        return w;
    end function key_expansion;

    function key_schedule_e (
        expanded_key : t_aes_expanded_key_word_array;
        round : integer)
        return std_logic_vector is
        variable round_key : std_logic_vector (BLOCK_TOP downto 0);
        constant start : integer := (round * Nb) + Nb - 1;
    begin

        for i in 0 to Nb - 1 loop
            round_key((i * 32) + 31 downto i * 32) := expanded_key(start - i);
        end loop;

        return round_key;

    end function key_schedule_e;

    function key_schedule_d (
        expanded_key : t_aes_expanded_key_word_array;
        round : integer)
        return std_logic_vector is
        variable round_key : std_logic_vector (BLOCK_TOP downto 0);
        constant start : integer := (round * Nb) + Nb - 1;
    begin
        -- works like forward key schedule with reversed indeces
        for i in 0 to Nb - 1 loop
            round_key((i * 32) + 31 downto i * 32) := expanded_key(start - i);
        end loop;
        if round /= 0 then
            round_key := mix_column_d(round_key);
        end if;

        return round_key;
    end function key_schedule_d;

    function get_key_byte (
        vector : std_logic_vector (KEY_TOP downto 0);
        index : integer)
        return std_logic_vector is
    begin
        return vector(KEY_TOP - (index * 8) downto KEY_TOP 
            - ((index + 1) * 8) + 1);
    end function get_key_byte;


end package body aes_package;
