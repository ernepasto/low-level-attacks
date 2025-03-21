start

break *main+577
commands
  silent
  set $random_variable = *(unsigned long long*)($rsi)
  printf "\nRandom value: %llx\n", $random_variable

break *main+686
commands
  silent
  set $rdx = $random_variable
  continue

end
continue
