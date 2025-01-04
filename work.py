# Python3 code to demonstrate working of
# Convert String to Tuple
# using map() + tuple() + int + split()

# initialize string
test_str = "abbacd"


# printing original string
print("The original string : " + str(test_str))

# Convert String to Tuple
# using map() + tuple() + int + split()
res = tuple(test_str.split())

# printing result
print("Tuple after getting conversion from String : " + str(res))
