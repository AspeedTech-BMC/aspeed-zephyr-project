# PLDM Firmware Update Package Generator

This tool creates a DSP0267 1.0 firmware update package from JSON metadata and
one or more component images.  It is based on the ASPEED-iROT package generator
and uses only the Python standard library.

```shell
./img.py output.pldm metadata.json component.bin
```

The component images must appear in the same order as the entries in
`ComponentImageInformationArea`.
