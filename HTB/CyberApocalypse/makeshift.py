#!/usr/bin/python3

scrambledFlag = '!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB'
scrambledFlag = scrambledFlag[::-1]
flag = ''

for i in range(0, len(scrambledFlag), 3):
    flag += scrambledFlag[i+1]
    flag += scrambledFlag[i+2]
    flag += scrambledFlag[i]

print(flag)