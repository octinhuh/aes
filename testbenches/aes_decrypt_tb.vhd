-- aes_decrypt_tb.vhd
-- testbench of the aes_decrypt component's functionality
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

entity aes_decrypt_tb is

end aes_decrypt_tb;

architecture test of aes_decrypt_tb is

-- components
component aes_decrypt
    port (
        clk : in std_logic;
        pt : in std_logic_vector (BLOCK_TOP downto 0);
        ct : out std_logic_vector (BLOCK_TOP downto 0);
        busy : out std_logic;
        key : in std_logic_vector (KEY_TOP downto 0);
        en : in std_logic;
        reset : in std_logic
    );
end component;

-- tb signals
signal pt, ct : std_logic_vector (BLOCK_TOP downto 0);
signal key : std_logic_vector (KEY_TOP downto 0);
signal busy, en, reset : std_logic;
signal clk : std_logic := '0';

constant CIPHER_TEXT : std_logic_vector (BLOCK_TOP downto 0)
    := x"8ea2b7ca516745bfeafc49904b496089";
constant KNOWN_ANSWER : std_logic_vector (BLOCK_TOP downto 0)
    := x"00112233445566778899aabbccddeeff";
constant CIPHER_KEY : std_logic_vector (KEY_TOP downto 0)
    := x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
--constant CIPHER_KEY : std_logic_vector (KEY_TOP downto 0)                     
--    := x"000102030405060708090a0b0c0d0e0f1011121314151617";
--constant CIPHER_KEY : std_logic_vector (KEY_TOP downto 0)                     
--    := x"000102030405060708090a0b0c0d0e0f";                                   

begin

    -- port mapping
    aes_decrypt_0 : aes_decrypt port map (clk=>clk, pt=>pt, ct=>ct, busy=>busy,
        key=>key, en=>en, reset=>reset);

    tb_process : process
    variable out_line : line;
    begin

        write(out_line, string'("Test of AES-256 decryption"));
        writeline(output, out_line);
        write(out_line, string'("CIPHER TEXT: "));
        hwrite(out_line, CIPHER_TEXT);
        writeline(output, out_line);
        write(out_line, string'("KEY:         "));
        hwrite(out_line, CIPHER_KEY);
        writeline(output, out_line);

        pt <= CIPHER_TEXT;
        key <= CIPHER_KEY;
        reset <= '0';
        en <= '1';
        wait for 10 ns;
        -- triggers round 0
        wait for 10 ns;
        en <= '0';

        wait until busy = '0';

        write(out_line, string'("OUTPUT:      "));
        hwrite(out_line, ct);
        writeline(output, out_line);
        write(out_line, string'("ANSWER:      "));
        hwrite(out_line, KNOWN_ANSWER);
        writeline(output, out_line);
        assert ct = KNOWN_ANSWER report "aes_decrypt output incorrect"
            severity error;

        wait;
    end process tb_process;

    clock : process
        variable round : integer := -1;
    begin
        wait for 10 ns;
        clk <= '1';
        wait for 10 ns;
        clk <= '0';
        round := round + 1;
        if round = 20 then
            wait;
        end if;
    end process clock;

end test;
