from tinyec import registry
import secrets

def compress(pubKey):
    return pubKey.x + pubKey.y % 2

def generate_keys():
    curve = registry.get_curve('brainpoolP256r1')  
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    return privKey, pubKey

#########################################################################################
"""The class example, y^2=(x^3 + x + 6)%11"""
# from tinyec.ec import SubGroup, Curve
#
# field = SubGroup(p=11, g=(2, 7), n=13, h=1)
# curve = Curve(a=1, b=6, field=field, name='p1707')
# print('curve:', curve)
#
# for k in range(0, 25):
#     p = k * curve.g
#     print(f"{k} * G = ({p.x}, {p.y})")
#########################################################################################