from charm.toolbox.integergroup import IntegerGroup
from charm.toolbox.ecgroup import ECGroup, G, ZR
from charm.toolbox.eccurve import prime192v1, secp256k1

# group1 = IntegerGroup()
# group1.paramgen(1024)

# g = group1.randomGen()

from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
group = ECGroup(secp256k1)

group2 = PairingGroup('SS512')
g1 = group2.random(G1)
g2 = group2.random(G1)
g3 = group2.random(G1)
g4 = group2.random(ZR)

print(type(group2))
print(type(g1))



print(f'g1 : {g1}')
print(f'g2 : {g2}')
# print(f'g3 : {g3}')

# p1 = pair(g1*g4, g2)
# p2 = pair(g1, g2) ** g4

p1 = g1
p2 = g1 ** g4
p3 = g1 ** (g4 ** -1)
p4 = g1 * g2

pairing1 = pair(p2, p3)
pairing2 = pair(g1, g1)

print(f"P1 : {p1}")
print(f"P2 : {p2}")
print(type(p2))
print(f"P3 : {p3}")
print(type(p3))
print(f"P4 : {p4}")
print(f"pairing1 : {pairing1}")
print(f"pairing2 : {pairing2}")
print(dir(p3))
# p = p.to_Zr()
# print(dir(p))



# def keygen():
#     g1, g2 = group.random(G), group.random(G)
#     x1, x2, y1, y2, z = group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR)
#     c = (g1 ** x1) * (g2 ** x2)
#     d = (g1 ** y1) * (g2 ** y2)
#     h = (g1 ** z)

#     pk = { 'g1' : g1, 'g2' : g2, 'c' : c, 'd' : d, 'h' : h, 'H' : group.hash }
#     sk = { 'x1' : x1, 'x2' : x2, 'y1' : y1, 'y2' : y2, 'z' : z }
#     return (pk, sk)

# print(keygen())