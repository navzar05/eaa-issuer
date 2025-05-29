import cascade
import hashlib
import pickle

R = set(["6456",
"12434",
"3",
"455"]) # Valid creds
S = set(["6245",
"23135",
"22",
"33"]
) # Revoked creds
r_hat = 50 # TODO genreaza-l pe baza formulei din articol

csd = cascade.Cascade()
csd1 = cascade.Cascade()

csd.build_cascade(R, S)

print(f"NO {csd.is_revoked("6456")}")
print(f"YES {csd.is_revoked("23135")}")


data = csd.serialize_cascade()

print(len(data))

with open("/home/razvan/Desktop/LICENTA/Proiect_Licenta3/backend/issuer/spring-issuer/cascade-bloom/src/output.bin", 'wb') as f:
    f.write(data)

with open("/home/razvan/Desktop/LICENTA/Proiect_Licenta3/backend/issuer/spring-issuer/cascade-bloom/src/output.bin", 'rb') as f:
    data = f.read()


csd1.deserialize_cascade(data)

# print(hashlib.sha1(pickle.dumps(csd.filters[7]['filter'].save_bytes())).digest())
# print(hashlib.sha1(pickle.dumps(csd1.filters[7]['filter'].save_bytes())).digest())


for cred in S:
    print(f"revoked : is revoked: {csd1.is_revoked(cred)}")
for cred in R:
    print(f"valid: is revoked: {csd1.is_revoked(cred)}")