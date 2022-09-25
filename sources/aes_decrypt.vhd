-- aes_decrypt.vhd
-- This is a definition of the aes_decrypt module
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

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

library work;
use work.aes_package.all;

entity aes_decrypt is
	port (
        clk : in std_logic;
        pt  : out std_logic_vector (BLOCK_TOP downto 0);
        ct  : in std_logic_vector (BLOCK_TOP downto 0);
        busy: out std_logic;
        key : in std_logic_vector (KEY_TOP downto 0);
        en  : in std_logic;
        reset : in std_logic
    );
end entity;

architecture behavioral of aes_decrypt is

    -- constants
    constant ROUND_MIN  : integer := 1;

    -- signals
    signal state : std_logic_vector (BLOCK_TOP downto 0);
    signal exp_key : t_aes_expanded_key_word_array;
    signal round : integer range 0 to Nr := 0;
    signal busy_t : std_logic;

    -- functions
    function do_round(
        s   : std_logic_vector(BLOCK_TOP downto 0);
        rk  : std_logic_vector(BLOCK_TOP downto 0))
        return std_logic_vector is
        variable ns : std_logic_vector(BLOCK_TOP downto 0);
    begin
        ns := shift_row_d(s);
        ns := sub_block_inv(ns);
        ns := add_round_key(ns, rk);
        ns := mix_column_d(ns);
        return ns;
    end function do_round;
    
    function do_final_round(
        s   : std_logic_vector(BLOCK_TOP downto 0);
        rk  : std_logic_vector(BLOCK_TOP downto 0))
        return std_logic_vector is
        variable ns : std_logic_vector(BLOCK_TOP downto 0);
    begin
        ns := shift_row_d(s);
        ns := sub_block_inv(ns);
        ns := add_round_key(ns, rk);
        return ns;
    end function do_final_round;

begin

    -- continuous assignments
    busy <= busy_t;

    clk_process : process (clk, en)
    begin
        -- uses asynchronous reset
        if reset = '1' then
            -- resetting the decryptor
            state <= std_logic_vector(to_unsigned(0, state'length));
            round <= 0;
            pt <= std_logic_vector(to_unsigned(0, pt'length));
            busy_t <= '0';
        elsif clk'event and clk = '1' then
            if en = '1' then
                -- latch key, start over process, reset cipher text
                round <= 0;
                pt <= std_logic_vector(to_unsigned(0, pt'length));
                exp_key <= key_expansion(key);
                busy_t <= '1';
            elsif busy_t = '1' then
                if round = 0 then
                    -- perform round 0
                    state <= add_round_key(ct, key_schedule_e(exp_key, 
                        Nr - round));
                    round <= round + 1;
                -- perform full rounds
                elsif round /= Nr then 
                    -- anything but the last round
                    state <= do_round(state, key_schedule_e(exp_key, 
                        Nr - round));
                    round <= round + 1;
                else
                    -- last round
                    pt <= do_final_round(state, key_schedule_e(exp_key,
                        Nr - round));
                    round <= 0;
                    busy_t <= '0';
                    state <= std_logic_vector(to_unsigned(0, state'length));
                end if;
            else
                -- avoid unintentional latching
                state <= state;
                round <= round;
                busy_t <= busy_t;
            end if;
        else
            -- avoid unintentional latching
            state <= state;
            round <= round;
            busy_t <= busy_t;
        end if;
    end process;

end behavioral;
