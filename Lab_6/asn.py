import asn1


def encode_file_signature(Q, p, curve, P, q, r, s):

    struct = asn1.Encoder()

    struct.start()

    struct.enter(asn1.Numbers.Sequence)

    struct.enter(asn1.Numbers.Set)

    struct.enter(asn1.Numbers.Sequence)

    struct.write(b"\x80\x06\x07\x00", asn1.Numbers.OctetString)
    struct.write(b"gostSignKey ", asn1.Numbers.UTF8String)

    struct.enter(asn1.Numbers.Sequence)
    struct.write(Q.x, asn1.Numbers.Integer)
    struct.write(Q.y, asn1.Numbers.Integer)
    struct.leave()

    struct.enter(asn1.Numbers.Sequence)
    struct.write(p, asn1.Numbers.Integer)
    struct.leave()

    struct.enter(asn1.Numbers.Sequence)
    struct.write(curve.a, asn1.Numbers.Integer)
    struct.write(curve.b, asn1.Numbers.Integer)
    struct.leave()

    struct.enter(asn1.Numbers.Sequence)
    struct.write(P.x, asn1.Numbers.Integer)
    struct.write(P.y, asn1.Numbers.Integer)
    struct.leave()

    struct.write(q, asn1.Numbers.Integer)
    struct.leave()

    struct.enter(asn1.Numbers.Sequence)
    struct.write(r, asn1.Numbers.Integer)
    struct.write(s, asn1.Numbers.Integer)
    struct.leave()

    struct.leave()

    struct.enter(asn1.Numbers.Sequence)
    struct.leave()

    struct.leave()

    return struct.output()


decoded_values = []


def parsing_file(file):

    while not file.eof():
        try:
            tag = file.peek()

            if tag.nr == asn1.Numbers.Null:
                break

            if tag.typ == asn1.Types.Primitive:
                tag, value = file.read()

                if tag.nr == asn1.Numbers.Integer:
                    decoded_values.append(value)
            else:
                file.enter()

                parsing_file(file)

                file.leave()

        except asn1.Error:
            break


def parse_file(filename):

    with open(filename, "rb") as file:
        data = file.read()

    file = asn1.Decoder()
    file.start(data)

    parsing_file(file)

    return decoded_values
