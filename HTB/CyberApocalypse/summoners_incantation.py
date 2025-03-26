# [11, 14, 6, 17, 9, 2, 20] = 51
# [13, 15, 4, 4] = 19
# [1, 7, 13, 14, 13] = 27
# [16, 20, 11, 4, 9, 15, 11, 6] = 48

from itertools import combinations

def non_adjacent_combinations(lst):
    n = len(lst)
    results = []
    
    # Generate all possible subsets using combinations
    for r in range(1, len(lst) + 1):  # Length of subsets
        for combo in combinations(range(n), r):  # Generate index combinations
            if all(combo[i] + 1 != combo[i + 1] for i in range(len(combo) - 1)):  # Ensure non-adjacency
                results.append([lst[i] for i in combo])
    return results

if __name__ == '__main__':
    input_text = "[11, 14, 6, 17, 9, 2, 20]"
    # Convert provided string to a list of integers
    input_text = input_text.strip('[').strip(']')
    input_list = input_text.split(',')
    il = list(map(int, input_list))
    # Retrieve all combinations of non-adjacent list items
    combos = non_adjacent_combinations(il)
    # sum all combinations of non-adjacent list items
    sums = []    
    for combo in combos:
        sums.append(sum(combo))
    # print the highest numerical value of sums
    print(max(sums))
