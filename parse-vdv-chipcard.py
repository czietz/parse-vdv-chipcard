#!/usr/bin/python

# parse-vdv-chipcard: Read and decode a VDV-KA contactless smart card

# Copyright (c) 2024 Christian Zietz

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from enum import IntEnum
from collections import OrderedDict
import sys

# Tags found on VDV-KA chip cards
class Tag(IntEnum):

    APPLIKATIONSVERZEICHNIS = 0xE0

    APPLIKATIONSDATEN = 0xE1
    VERZ_APPLIKATIONSDATEN = 0xE2
    APPLIKATIONSDATEN_DYNAMISCH = 0x80
    APPLIKATIONSDATEN_STATISCH = 0x81
    APPLIKATIONSDATEN_SEPARATE_DATEN = 0xEE
    SCHLUESSELVERSIONEN = 0x91
    AUSGABETRANSAKTIONSKENNUNG = 0x99

    APPLIKATIONSLOGBUCH = 0xE3
    VERZ_APPLIKATIONSLOGBUCH = 0xE4
    APPLIKATIONSLOGBUCH_STATISCH = 0x82
    APPLIKATIONSLOGBUCH_SEPARATE_DATEN = 0xE5

    KUNDENDATEN = 0xE6
    VERZ_KUNDENDATEN = 0xE7

    BERECHTIGUNG = 0xE8
    VERZ_BERECHTIGUNG = 0xE9
    BERECHTIGUNG_STATISCH = 0x83
    BERECHTIGUNG_DYNAMISCH = 0x84
    BERECHTIGUNG_SEPARATE_DATEN = 0xEA
    BERECHTIGUNG_PRODUKTSPEZIFISCH = 0x85

    SCHLUESSELREGISTER = 0xEB
    VERZ_SCHLUESSELREGISTER = 0xEC
    SCHLUESSELREGISTER_STATISCH = 0x86
    SCHLUESSELREGISTER_DYNAMISCH = 0x87
    SCHLUESSELREGISTER_SEPARATE_DATEN = 0xED

    ALLGEMEINE_TRANSAKTIONSDATEN = 0x89
    AUSGABETRANSAKTION_APPLIKATION = 0xF7
    STATUSAENDERUNG_APPLIKATION = 0x8E
    AUSGABE_APPLIKATION_DATEN = 0x9B

    AUSGABETRANSAKTION_BERECHTIGUNG = 0xF6
    TRANSAKTION_PRODUKTSPEZIFISCHER_TEIL = 0x8A
    STATUSAENDERUNG_BERECHTIGUNG = 0x8D
    AUSGABE_BERECHTIGUNG_DATEN = 0x9A

    FAHRTTRANSAKTION = 0xF1
    ALLGEMEINE_FAHRTTRANSAKTIONSDATEN = 0x8B

    # TLV-EFS tags
    TLV_EFS_GRUNDLEGENDE_DATEN = 0xDA
    TLV_EFS_FAHRGAST = 0xDB
    TLV_EFS_LISTE_ORIG_GELTUNGSBEREICH = 0xDC

    ZEIGER = 0xC0
    LETZTE_TRANSAKTION = 0xC3
    INFOTEXT = 0xC7
    PRIORITAETEN = 0x90

# A decoder for values stored in VDV-KA tags
class VdvKaDecoder:

    # Tags and field definitions:
    # fields are separated by '|' and consist of a data type and a name
    _fields = {
        Tag.APPLIKATIONSDATEN_DYNAMISCH: "1:appStatus|1:appSynchronNummer",
        Tag.APPLIKATIONSDATEN_STATISCH: "4:NmAppInstanznummer|2:app.organisationsNummer|1:appVersion|D:appGueltigkeitsbeginn|D:appGueltigkeitsende",
        Tag.APPLIKATIONSLOGBUCH_STATISCH: "2:logApplikationSeqNummer",
        Tag.INFOTEXT: "S:Infotext",
        Tag.SCHLUESSELVERSIONEN: "1:Version KPV|1:Version KKVP|1:Version KAUTH",
        Tag.AUSGABETRANSAKTIONSKENNUNG: "4:samSequenznummer|3:samNummer",
        Tag.ALLGEMEINE_TRANSAKTIONSDATEN: "2:logApplikationSeqNummer|4:samSequenznummer|3:samNummer|2:logTransaktionsOperator_ID|1:terminalTyp|2:terminalNummer|2:transkation.organisationsNummer|D:logTransaktionsZeitpunkt|1:ortTyp|3:ortNummer|2:ort.organisationsNummer|1:logTransaktionsTyp",
        Tag.AUSGABE_APPLIKATION_DATEN: "4:appProdLogSAMSeqNummer",
        Tag.STATUSAENDERUNG_APPLIKATION: "2:appLogSeqNummer|4:NmAppInstanznummer|2:app.organisationsNummer|1:alterStatus|1:neuerStatus|1:appSynchronNummer|8:MACKONTROLLE|1:Version KKONTROLLE",
        Tag.AUSGABE_BERECHTIGUNG_DATEN: "4:berProdLogSAMSeqNummer",
        Tag.STATUSAENDERUNG_BERECHTIGUNG: "2:berLogSeqNummer|4:berechtigungNummer|2:ber.organisationsNummer|2:produktNummer|2:produkt.organisationsNummer|1:alterStatus|1:neuerStatus|1:berSynchronNummer|8:MACKONTROLLE|1:Version KKONTROLLE",
        Tag.SCHLUESSELREGISTER_STATISCH: "2:|2:hersteller.organisationsNummer|B:NM-Spezifikations-version|4:Herstellerspezifische Versionsnummer",
        Tag.BERECHTIGUNG_STATISCH: "4:berechtigungNummer|2:ber.organisationsNummer|2:produktNummer|2:produkt.organisationsNummer|2:prodKeyOrganisation_ID|D:berGueltigkeitsbeginn|D:berGueltigkeitsende",
        Tag.BERECHTIGUNG_DYNAMISCH: "1:berStatus|1:berSynchronNummer",
        Tag.TLV_EFS_FAHRGAST: "1:efsFahrgastGeschlecht|H:efsFahrgastGeburtsdatum|S:efsFahrgastName",
        Tag.TLV_EFS_LISTE_ORIG_GELTUNGSBEREICH: "1:Typ|2:pv.organisationsNummer",
        Tag.LETZTE_TRANSAKTION: "1:LogTransaktionsTyp|1:Zeiger",
        Tag.ALLGEMEINE_FAHRTTRANSAKTIONSDATEN: "2:berLogSeqNummer|4:berechtigungNummer|2:ber.organisationsNummer|2:produktNummer|2:produkt.organisationsNummer|2:Linie_ID.linienNummer|1:VariantenNummer|3:fahrtNummer|2:Organisation_ID.organisationsNummer"
    }

    # DateTimeCompact is a four-byte encoding of date and time
    @staticmethod
    def _decode_datetimecompact(dt):
        year = (dt >> (16+9)) + 1990
        month = (dt >> (16+5)) & 0xF
        day = (dt >> 16) & 0x1F
        hour = (dt >> 11) & 0x1F
        min = (dt >> 5) & 0x3F
        sec = (dt & 0x1F) * 2
        return (year,month,day,hour,min,sec)

    @staticmethod
    def _decode_internal(idata, fdef):
        result = OrderedDict() # note: starting with Python 3.6, the default dict is also ordered
        for field in fdef.split("|"):
            type,name = field.split(":")

            if type == "1": # one byte
                val = next(idata)
            elif type == "2": # two byte number
                val = (next(idata) << 8) + next(idata)
            elif type == "3": # three byte number
                val = (next(idata) << 16) + (next(idata) << 8) + next(idata)
            elif type == "4": # four byte number
                val = (next(idata) << 24) + (next(idata) << 16) + (next(idata) << 8) + next(idata)
            elif type == "8": # eight byte hex string
                val = "".join(["%02x" % next(idata) for x in range(8)])
            elif type == "B": # 2 byte BCD
                val = "".join(["%02x" % next(idata) for x in range(2)])
            elif type == "D": # DateTimeCompact
                val = (next(idata) << 24) + (next(idata) << 16) + (next(idata) << 8) + next(idata)
                val = VdvKaDecoder._decode_datetimecompact(val)
                val = "%04d-%02d-%02d %02d:%02d:%02d" % val
            elif type == "H": # hex/bcd coded date
                val = "%02x%02x-%02x-%02x" % (next(idata), next(idata), next(idata), next(idata))
            elif type == "S": # string until end of data
                val = "".join([chr(x) for x in idata])
            else:
                raise(ValueError("Unknown data type: "+type))

            if name != "":
                result[name] = val
        return result

    @staticmethod
    def decode(tag, data):
        try:
            fdef  = VdvKaDecoder._fields[tag]
            return VdvKaDecoder._decode_internal(iter(data), fdef)
        except KeyError:
            return None

# A parser for BER-TLV encoded data
class BerTlv:

    def __init__(self, data=[]):
        if (data == []) or (self._is_nested_tlv(data)):
            self._bertlv = data
        else:
            self.parse(data)

    def __iter__(self):
        for tlv in self._bertlv:
            tag,length,value = tlv
            yield tag

    def __add__(self, x):
        if isinstance(x, BerTlv):
            return BerTlv(self._bertlv + x._bertlv)
        else:
            temp = BerTlv(x)
            return self + temp

    # Recursive parser for BER-TLV data
    def _parse_internal(self, data, tlvefs_hack):
        idata = iter(data)
        decoded = []
        try:
            while True:
                tag = next(idata)
                length = next(idata)
                if length & 0x80:
                    # length long form: read actual length from following octets
                    n = length & 0x7f
                    length = 0
                    for k in range(n):
                        length = (length<<8) | next(idata)
                value = [next(idata) for k in range(length)]

                # Note that tag 0xED needs special handling: it has the bit for a constructed tag,
                # but is actually not a constructed tag in the current version of the VDV-KA.
                # Also tag 0x85 might require a special handling, because in case of a TLV EFS it
                # is a constructed that, even though the respective bit is not set.
                if ((tag & 0x20 != 0) and (tag != Tag.SCHLUESSELREGISTER_SEPARATE_DATEN)) or (tlvefs_hack and (tag == Tag.BERECHTIGUNG_PRODUKTSPEZIFISCH)):
                    # constructed tag, decode recursively
                    inner = self._parse_internal(value, tlvefs_hack)
                    decoded = decoded + [[tag,length,inner]]
                else:
                    decoded = decoded + [[tag,length,value]]
        except StopIteration:
            return decoded

    # Parse a BER-TLV encoded list of bytes
    def parse(self, data, tlvefs_hack = False):
        self._bertlv = self._parse_internal(data, tlvefs_hack)

    @staticmethod
    def _is_nested_tlv(value):
        return len(value)>0 and isinstance(value[0], list)

    # Get the n-th child (constructed tag)
    def get_nth_child(self, tag, no):
        count = 0
        for tlv in self._bertlv:
            temp,length,value = tlv
            if temp == tag:
                if count == no and self._is_nested_tlv(value):
                    ret = BerTlv(value)
                    return ret
                count += 1
        return None

    # Get the first/only child (constructed tag)
    def get_child(self, tag):
        return self.get_nth_child(tag, 0)

    # Get the value of a tag
    def get_value(self, tag):
        for tlv in self._bertlv:
            temp,length,value = tlv
            if temp == tag:
                if not self._is_nested_tlv(value):
                    return bytes(value)
        return None

    # Try to decode the tag name
    @staticmethod
    def _get_tag_name(tag):
        try:
            return "%02x (%s)" % (tag, Tag(tag).name)
        except ValueError:
            return "%02x (???)" % tag

    def _pretty_print_internal(self, data, with_names, with_details, indent):
        for tlv in data:
            tag,length,value = tlv
            if with_names:
                tag_name = self._get_tag_name(tag)
            else:
                tag_name = "%02x" % tag
            if self._is_nested_tlv(value):
                # nested list
                print("%s%s:" % ("  "*indent, tag_name))
                self._pretty_print_internal(value, with_names, with_details, indent+1)
            else:
                print("%s%s:" % ("  "*indent, tag_name), *["%02x"%x for x in value])
                if with_details and ((decoded := VdvKaDecoder.decode(tag, value)) is not None):
                    for n,v in decoded.items():
                        print("  "*indent + "  " + n + ": " +str(v))

    # Pretty-print the data
    def pretty_print(self, with_names = False, with_details = False):
        self._pretty_print_internal(self._bertlv, with_names, with_details, 0)

# APDUs used when communicating with card
SELECT_VDV_KA = [0x00, 0xA4, 0x04, 0x0C, 0x0C, 0xD2, 0x76, 0x00, 0x01, 0x35, 0x4B, 0x41, 0x4E, 0x4D, 0x30, 0x31, 0x00, 0x00]
GET_DATA_NEXT = [0x10, 0xCA, 0x01, 0xF0, 0x02]
GET_DATA_LAST = [0x00, 0xCA, 0x01, 0xF0, 0x02]

# SW1SW2 = 0x9000 indicates a successful transaction
def success(sw1, sw2):
    return sw1 == 0x90 and sw2 == 00

# Use chained mode to read data structures that might be longer than 256 bytes
def read_chained_data(connection, record):
    full_data = []
    while True:
        response, sw1, sw2 = connection.transmit(GET_DATA_NEXT + record + [0x00])
        full_data = full_data + response
        if not success(sw1,sw2):
            return full_data, sw1, sw2
        # reached last record
        if len(response) < 256:
            break
    # this command will not return further data, but needs to be sent to end chained mode
    response, sw1, sw2 = connection.transmit(GET_DATA_LAST + record + [0x00])
    return full_data, sw1, sw2

# Parse and pretty print TLV data
def pretty_print_block(response, sw1, sw2):
    if success(sw1,sw2):
        t = BerTlv(response)
        # heuristic to guess if we have a TLV-EFS (which needs special parsing):
        # if there is a tag 0x85 ('Statischer Produktspezifischer Teil') and its
        # value starts with 0xD?, assume this is a TLV-EFS with nested tags and reparse
        try:
            is_tlv_efs = (t.get_child(Tag.BERECHTIGUNG).get_child(Tag.BERECHTIGUNG_SEPARATE_DATEN).get_value(Tag.BERECHTIGUNG_PRODUKTSPEZIFISCH)[0] & 0xF0) == 0xD0
        except AttributeError:
            is_tlv_efs = False
        if is_tlv_efs:
            t.parse(response, True)
        t.pretty_print(True, True)
    else:
        print("Fehler %02x%02x" % (sw1,sw2))
    print("")

# Find the reader with the VDV-KA card and read the 'Applikationsverzeichnis'
for reader in readers():
    try:
        connection = reader.createConnection()
        connection.connect()
        # try to select VDV-KA application
        response, sw1, sw2 = connection.transmit(SELECT_VDV_KA)
        # selection successful?
        if success(sw1,sw2):
            break
        else:
            print(str(reader) + ": Keine VDV-KA Applikation: Fehler %02x%02x" % (sw1,sw2))
    except NoCardException:
        print(str(reader) + ": Keine Karte")
else:
    print("Kein Leser / keine VDV-KA-Karte gefunden")
    sys.exit(1)

# Print the 'Applikationsverzeichnis' that was returned upon selection of the application
print("=== APPLIKATIONSVERZEICHNIS ===")
m = BerTlv(response)
m.pretty_print(True, True)
print("")

# Read and print the 'Applikationsdaten'
print("=== APPLIKATIONSDATEN ===")
appl_daten_zeiger,*_ = m.get_child(Tag.APPLIKATIONSVERZEICHNIS).get_child(Tag.VERZ_APPLIKATIONSDATEN).get_value(Tag.ZEIGER)
response, sw1, sw2 = read_chained_data(connection, [Tag.APPLIKATIONSDATEN, appl_daten_zeiger])
pretty_print_block(response, sw1, sw2)

# Read and print the 'Applikationslogbuch'
print("=== APPLIKATIONSLOGBUCH ===")
appl_log_zeiger,*_ = m.get_child(Tag.APPLIKATIONSVERZEICHNIS).get_child(Tag.VERZ_APPLIKATIONSLOGBUCH).get_value(Tag.ZEIGER)
response, sw1, sw2 = read_chained_data(connection, [Tag.APPLIKATIONSLOGBUCH, appl_log_zeiger])
pretty_print_block(response, sw1, sw2)

# Do NOT read and print the 'Kundendaten' as they are protected by a PIN
if False:
    print("=== KUNDENDATEN ===")
    kundendat_zeiger,*_ = m.get_child(Tag.APPLIKATIONSVERZEICHNIS).get_child(Tag.VERZ_KUNDENDATEN).get_value(Tag.ZEIGER)
    response, sw1, sw2 = read_chained_data(connection, [Tag.KUNDENDATEN, kundendat_zeiger])
    pretty_print_block(response, sw1, sw2)

# Read and print the 'Schlüsselregister' for 'Multiberechtigungen' assuming the app version is high enough
app_version = m.get_child(Tag.APPLIKATIONSVERZEICHNIS).get_child(Tag.VERZ_APPLIKATIONSDATEN).get_value(Tag.APPLIKATIONSDATEN_STATISCH)[6]
if app_version >= 0x11:
    print("=== SCHLÜSSELREGISTER ===")
    schlreg_zeiger,*_ = m.get_child(Tag.APPLIKATIONSVERZEICHNIS).get_child(Tag.VERZ_SCHLUESSELREGISTER).get_value(Tag.ZEIGER)
    response, sw1, sw2 = read_chained_data(connection, [Tag.SCHLUESSELREGISTER, schlreg_zeiger])
    pretty_print_block(response, sw1, sw2)

# Read and print at most 16 'Berechtigungen'
for nber in range(16):

    try:
        ber_zeiger,*_ = m.get_child(Tag.APPLIKATIONSVERZEICHNIS).get_nth_child(Tag.VERZ_BERECHTIGUNG, nber).get_value(Tag.ZEIGER)
    except AttributeError:
        # no further 'Berechtigungen'
        break

    print("=== BERECHTIGUNG #%d ===" % (nber+1))
    response, sw1, sw2 = read_chained_data(connection, [Tag.BERECHTIGUNG, ber_zeiger])
    pretty_print_block(response, sw1, sw2)