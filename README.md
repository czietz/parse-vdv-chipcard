# Read and decode a VDV-KA contact-less smart card

This little Python script reads German public transport tickets stored on a contact-less smart card that adheres to the [VDV-KA standard](https://www.eticket-deutschland.de/eticket/vdv-ka-und-eticore/) and decodes the content. Note that the standard itself is not publicly available and not all field names are self-explanatory.

Requirements: The [pyscard library](https://github.com/LudovicRousseau/pyscard) and a smart card reader supported by it.