# Address Scaling

Real-world traces address tens of GiB to multiple TiB of LBA space.
The FEMU simulated SSD is 12,288 MiB.
`scale_iologs.py` remaps every trace to fit via an affine transform.

## Transform

```
a'ᵢ = floor( (aᵢ − a_min) × s  /  B ) × B
```

where:

```
s = min( 1,  floor(C × α) / (a_max − a_min) )
```

| Symbol  | Value / definition                                          |
|---------|-------------------------------------------------------------|
| `aᵢ`   | original byte offset of request *i*                         |
| `a_min` | min offset across **all segments** of the unit (warmup + short + long) |
| `a_max` | max offset across all segments of the unit                  |
| `C`     | device capacity = 12,884,901,888 B (12,288 MiB)            |
| `α`     | usable fraction = 0.95                                      |
| `s`     | scale factor (≤ 1)                                          |
| `B`     | alignment = 4,096 B                                         |
| `a'ᵢ`  | scaled offset, guaranteed in `[0, floor(C × α))`           |

