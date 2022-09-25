-- aes_package_tb.vhd
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
use IEEE.STD_LOGIC_TEXTIO.ALL;
use STD.TEXTIO.ALL;
use IEEE.NUMERIC_STD.ALL;

library work;
use work.aes_package.all;

entity aes_package_tb is

end aes_package_tb;

architecture test of aes_package_tb is

    -- tb signals
    signal flag : std_logic := '0';
    signal t, k, s : std_logic_vector (BLOCK_TOP downto 0);
    signal b : std_logic_vector (7 downto 0);
    signal w : std_logic_vector (31 downto 0);
    signal e : t_aes_expanded_key_word_array;
    signal r : integer;
    constant IN_E : std_logic_vector (BLOCK_TOP downto 0)
        := x"63637c7c_7b7bc5c5_7676c0c0_7575d2d2";
    constant IN_D : std_logic_vector (BLOCK_TOP downto 0)
        := x"637bc0d2_7b76d27c_76757cc5_7563c5c0";
    constant TEST_VECTOR_1 : std_logic_vector (BLOCK_TOP downto 0)
        := x"01234567_89abcdef_01234567_89abcdef";
    constant TEST_VECTOR_2 : std_logic_vector (BLOCK_TOP downto 0)
        := x"00112233_44556677_8899aabb_ccddeeff";
    constant TEST_VECTOR_3 : std_logic_vector (BLOCK_TOP downto 0)
        := x"8ea2b7ca_516745bf_eafc4990_4b496089";
    constant MC_E_IN : std_logic_vector (BLOCK_TOP downto 0)
        := x"6353e08c0960e104cd70b751bacad0e7";
    constant MC_E_OUT : std_logic_vector (BLOCK_TOP downto 0)
        := x"5f72641557f5bc92f7be3b291db9f91a";
    constant MC_D_IN : std_logic_vector (BLOCK_TOP downto 0)
        := x"627bceb9999d5aaac945ecf423f56da5";
    constant MC_D_OUT : std_logic_vector (BLOCK_TOP downto 0)
        := x"e51c9502a5c1950506a61024596b2b07";
    constant CIPHER_KEY : std_logic_vector (KEY_TOP downto 0)
        := x"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    constant CIPHER_KEY_2 : std_logic_vector (KEY_TOP downto 0)
        := x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    constant ALL_ZEROS : std_logic_vector (t'range) := (others => '0');
begin

    tb_process : process
    variable out_line : line;
    begin
        -- shift_row
        write(out_line, string'("Test of shift_row encrypt and decrypt"));
        writeline(output, out_line);

        write(out_line, string'("Input to shift_row_e:  "));
        hwrite(out_line, IN_E);
        writeline(output, out_line);
        
        t <= shift_row_e(IN_E);
        wait for 10 ns;
        write(out_line, string'("Output of shift_row_e: "));
        hwrite(out_line, t);
        writeline(output, out_line);
        assert t = IN_D report "shift_row_e output incorrect" severity error;
        
        write(out_line, string'("Input to shift_row_d:  "));
        hwrite(out_line, IN_D);
        writeline(output, out_line);

        t <= shift_row_d(IN_D);
        wait for 10 ns;
        write(out_line, string'("Output of shift_row_d: "));
        hwrite(out_line, t);
        writeline(output, out_line);
        assert t = IN_E report "shift_row_d output incorrect" severity error;

        -- add_round_key
        writeline(output, out_line);
        write(out_line, string'("Test of add_round_key"));
        writeline(output, out_line);

        t <= add_round_key(a => TEST_VECTOR_1, k => TEST_VECTOR_1);
        wait for 10 ns;

        write(out_line, string'("Key:                     "));
        hwrite(out_line, TEST_VECTOR_1);
        writeline(output, out_line);
        write(out_line, string'("State vector:            "));
        hwrite(out_line, TEST_VECTOR_1);
        writeline(output, out_line);
        write(out_line, string'("Output of add_round_key: "));
        hwrite(out_line, t);
        writeline(output, out_line);
        assert t = ALL_ZEROS report
            "add_round_key output incorrect" severity error;

        -- s_box
        writeline(output, out_line);
        write(out_line, string'("Test of s_box"));
        writeline(output, out_line);
        flag <= '1';

        for i in 0 to 255 loop
            b <= s_box_inv(s_box(std_logic_vector(to_unsigned(i, b'length))));
            wait for 10 ns;
            if b /= std_logic_vector(to_unsigned(i, b'length)) then
                flag <= '0';
            else
                flag <= flag;
            end if;
            assert b = std_logic_vector(to_unsigned(i, b'length))
                report "s_box output not matched" severity error;
        end loop;
        if flag = '1' then
            write(out_line, string'("s_box test passed"));
            writeline(output, out_line);
        else
            write(out_line, string'("s_box test failed"));
            writeline(output, out_line);
        end if;

        -- sub_block test, encompasses sub_word, by extension. If s_box test
        -- passed, then this test should also be successful
        writeline(output, out_line);
        write(out_line, string'("Test of sub_block encrypt and decrypt"));
        writeline(output, out_line);
        
        t <= sub_block_inv(sub_block(IN_E));
        wait for 10 ns;

        write(out_line, string'("State: "));
        hwrite(out_line, IN_E);
        writeline(output, out_line);
        write(out_line, string'("S-box: "));
        hwrite(out_line, sub_block(IN_E));
        writeline(output, out_line);
        assert t = IN_E report "sub_block or sub_block_inv output incorrect"
            severity error;

        -- mix_column_e
        writeline(output, out_line);
        write(out_line, string'("Test of mix_column encrypt"));
        writeline(output, out_line);

        t <= mix_column_e(MC_E_IN);
        wait for 10 ns;

        write(out_line, string'("State:        "));
        hwrite(out_line, MC_E_IN);
        writeline(output, out_line);
        write(out_line, string'("mix_column_e: "));
        hwrite(out_line, t);
        writeline(output, out_line);
        assert t = MC_E_OUT report 
            "mix_column_e output incorrect" severity error;

        -- mix_column_d
        writeline(output, out_line);
        write(out_line, string'("Test of mix_column decrypt"));
        writeline(output, out_line);

        t <= mix_column_d(MC_D_IN);
        wait for 10 ns;

        write(out_line, string'("State:        "));
        hwrite(out_line, MC_D_IN);
        writeline(output, out_line);
        write(out_line, string'("mix_column_d: "));
        hwrite(out_line, t);
        writeline(output, out_line);
        assert t = MC_D_OUT report 
            "mix_column_d output incorrect" severity error;

        -- key expansion
        writeline(output, out_line);
        write(out_line, string'("Test of key expansion"));
        writeline(output, out_line);
        write(out_line, string'("Key: "));
        hwrite(out_line, CIPHER_KEY);
        writeline(output, out_line);

        e <= key_expansion(CIPHER_KEY);
        wait for 10 ns;

        for i in 0 to EXPANDED_WORDS_TOP loop
            write(out_line, i);
            write(out_line, string'(": "));
            hwrite(out_line, e(i));
            writeline(output, out_line);
        end loop;

        -- test key_schedule (encryption)
        writeline(output, out_line);
        write(out_line, string'("Test of key schedule (encryption)"));
        writeline(output, out_line);
        write(out_line, string'("Key: "));
        hwrite(out_line, CIPHER_KEY);
        writeline(output, out_line);

        -- using expanded key from key_expansion (better hope that worked)
        for i in 0 to 14 loop
            write(out_line, string'("Round "));
            write(out_line, i);
            write(out_line, string'(": "));
            hwrite(out_line, key_schedule_e(e, i));
            writeline(output, out_line);
        end loop;


        -- test key_schedule (decryption)
        writeline(output, out_line);
        write(out_line, string'("Test of key schedule (decryption)"));
        writeline(output, out_line);
        write(out_line, string'("Key: "));
        hwrite(out_line, CIPHER_KEY_2);
        writeline(output, out_line);

        e <= key_expansion(CIPHER_KEY_2);
        wait for 10 ns;

        -- using expanded key from key_expansion (better hope that worked)
        for i in 0 to 14 loop
            write(out_line, string'("Round "));
            write(out_line, i);
            write(out_line, string'(": "));
            hwrite(out_line, key_schedule_d(e, i));
            writeline(output, out_line);
        end loop;

        -- get_key_byte
        writeline(output, out_line);
        write(out_line, string'("Test of get_key_byte"));
        writeline(output, out_line);
        write(out_line, string'("Key: "));
        hwrite(out_line, CIPHER_KEY);
        writeline(output, out_line);

        for i in 0 to ((KEY_TOP + 1) / 8) - 1 loop
            write(out_line, string'("byte "));
            write(out_line, i);
            write(out_line, string'(": "));
            hwrite(out_line, get_key_byte(CIPHER_KEY, i));
            writeline(output, out_line);
        end loop;

        -- simulation of decrypt
        writeline(output, out_line);
        write(out_line, string'("Running decrypt operation in full"));
        writeline(output, out_line);
        write(out_line, string'("PLAINTEXT:"));
        write(out_line, ht);
        hwrite(out_line, TEST_VECTOR_3);
        writeline(output, out_line);
        write(out_line, string'("KEY:       "));
        write(out_line, ht);
        hwrite(out_line, CIPHER_KEY_2);
        writeline(output, out_line);

        e <= key_expansion(CIPHER_KEY_2);
        r <= 0;
        s <= TEST_VECTOR_3;
        wait for 10 ns;
        k <= key_schedule_e(e, Nr - r);
        wait for 10 ns;

        -- round 0
        write(out_line, string'("round["));
        write(out_line, r);
        write(out_line, string'("].iinput"));
        write(out_line, ht);
        hwrite(out_line, s);
        writeline(output, out_line);
        write(out_line, string'("round["));
        write(out_line, r);
        write(out_line, string'("].ik_sch"));
        write(out_line, ht);
        hwrite(out_line, k);
        writeline(output, out_line);
        s <= add_round_key(s, k);
        wait for 10 ns;

        -- the rounds 1-13
        for i in 1 to Nr - 1 loop

            write(out_line, string'("round["));
            write(out_line, i);
            write(out_line, string'("].istart"));
            write(out_line, ht);
            hwrite(out_line, s);
            writeline(output, out_line);
            s <= shift_row_d(s);
            wait for 10 ns;
            write(out_line, string'("round["));
            write(out_line, i);
            write(out_line, string'("].is_row"));
            write(out_line, ht);
            hwrite(out_line, s);
            writeline(output, out_line);
            s <= sub_block_inv(s);
            wait for 10 ns;
            write(out_line, string'("round["));
            write(out_line, i);
            write(out_line, string'("].is_box"));
            write(out_line, ht);
            hwrite(out_line, s);
            writeline(output, out_line);
            k <= key_schedule_e(e, Nr - i);
            s <= add_round_key(s, key_schedule_e(e, Nr - i));
            wait for 10 ns;
            write(out_line, string'("round["));
            write(out_line, i);
            write(out_line, string'("].ik_sch"));
            write(out_line, ht);
            hwrite(out_line, k);
            writeline(output, out_line);
            write(out_line, string'("round["));
            write(out_line, i);
            write(out_line, string'("].ik_add"));
            write(out_line, ht);
            hwrite(out_line, s);
            writeline(output, out_line);
            s <= mix_column_d(s);
            wait for 10 ns;
        end loop;

        -- last round
        write(out_line, string'("round["));
        write(out_line, Nr);
        write(out_line, string'("].istart"));
        write(out_line, ht);
        hwrite(out_line, s);
        writeline(output, out_line);
        s <= shift_row_d(s);
        wait for 10 ns;
        write(out_line, string'("round["));
        write(out_line, Nr);
        write(out_line, string'("].is_row"));
        write(out_line, ht);
        hwrite(out_line, s);
        writeline(output, out_line);
        s <= sub_block_inv(s);
        wait for 10 ns;
        write(out_line, string'("round["));
        write(out_line, Nr);
        write(out_line, string'("].is_box"));
        write(out_line, ht);
        hwrite(out_line, s);
        writeline(output, out_line);
        k <= key_schedule_e(e, Nr - Nr);
        s <= add_round_key(s, key_schedule_e(e, Nr - Nr));
        wait for 10 ns;
        write(out_line, string'("round["));
        write(out_line, Nr);
        write(out_line, string'("].ik_sch"));
        write(out_line, ht);
        hwrite(out_line, k);
        writeline(output, out_line);
        write(out_line, string'("round["));
        write(out_line, Nr);
        write(out_line, string'("].ioutput"));
        write(out_line, ht);
        hwrite(out_line, s);
        writeline(output, out_line);
        wait;
    end process tb_process;

end test;
