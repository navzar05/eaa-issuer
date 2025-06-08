import random

total = 10_000_000
revoked_count = total * 15 // 100
revoked_ids = set(random.sample(range(total), revoked_count))

with open("random_revocation_list.txt", "w") as f:
    for i in range(total):
        state = 1 if i in revoked_ids else 0
        f.write(f"{i}:{state}\n")
