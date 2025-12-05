# Noesis UI Framework in BG3

## Overview

Baldur's Gate 3 uses the **Noesis GUI** framework (NoesisGUI) for its user interface. This is a commercial XAML-based UI framework that runs on multiple platforms including macOS.

## Noesis FixedString (NOT Larian FixedString)

**Important Distinction:** Noesis has its own `Noesis::FixedString<N>` template class which is completely separate from Larian's `ls::FixedString`. They should not be confused:

| Feature | Noesis::FixedString<N> | ls::FixedString |
|---------|------------------------|-----------------|
| Namespace | `Noesis` | `ls` |
| Implementation | Fixed-size inline buffer | Index into GlobalStringTable |
| Size | Template parameter (24, 64, 128, 256, etc.) | Always 4 bytes (index) |
| Storage | Inline string data | Reference to pooled string |

## Discovered Noesis Symbols

### FixedString Templates Found in Binary

| Template Size | Example Symbol Address |
|--------------|----------------------|
| `FixedString<24>` | `0x1002f1554` (destructor) |
| `FixedString<32>` | `0x10058f090` |
| `FixedString<64>` | `0x1004e2de0` |
| `FixedString<128>` | `0x10033bf94` |
| `FixedString<180>` | `0x10058e928` |
| `FixedString<256>` | `0x1004354cc` |
| `FixedString<512>` | `0x1002f18c4` |
| `FixedString<1024>` | `0x100339b44` |

### Key Noesis Functions

| Function | Address | Purpose |
|----------|---------|---------|
| `Noesis::FixedString<24>::FixedString(const char*)` | `0x100307508` | Constructor |
| `Noesis::FixedString<24>::~FixedString()` | `0x1002f1554` | Destructor |
| `Noesis::FixedString<24>::FixedString(VarArgs, const char*, ...)` | `0x100346afc` | Variadic constructor |
| `Noesis::Impl::ToString(FixedString<24>&)` | `0x100346e78` | String conversion |

### Noesis Property System Integration

Noesis uses `FixedString<24>` extensively in its property system:

- `DependencyData::RegisterProperty<FixedString<24>>` at `0x1002f14ac`
- `PropertyMetadata::Create<FixedString<24>>` at `0x1002f14b8`
- `DependencyObject::SetValue_<FixedString<24>>` at `0x1002f1704`
- `FrameworkPropertyMetadata::Create<FixedString<24>>` at `0x1004581ec`

### Noesis HashMap with FixedString Keys

Noesis has its own HashMap implementation that uses FixedString as keys:

```cpp
// Example: Font cache with FixedString<24> keys
HashMapImpl<HashBucket_KHV<FixedString<24>, CachedFontProvider::Face, ...>>
```

Found at addresses like `0x100432010`, `0x1004333bc`, etc.

### Noesis BoxedValue System

The `Boxed<FixedString<24>>` class wraps FixedString for the property system:

- Constructor: `0x1002f3338`
- Destructor: `0x1002f347c`
- GetClassType: `0x1002f3514`
- ToString: `0x1002f3650`
- Equals: `0x1002f3658`

## Relationship to BG3 Modding

### UI Modding Implications

1. **XAML Resources**: BG3's UI is defined in XAML files that Noesis parses
2. **Data Binding**: Uses `FixedString<24>` for property binding paths
3. **Custom Controls**: BG3 likely has custom Noesis controls in the `NoesisApp` namespace

### Discovered NoesisApp Enums

These enums are used for UI behaviors:

| Enum | Address Range |
|------|--------------|
| `ComparisonConditionType` | `0x1002e9afc` |
| `ForwardChaining` | `0x1002ea1ec` |
| `KeyTriggerFiredOn` | `0x1002ea8cc` |
| `GamepadTriggerFiredOn` | `0x1002eafac` |
| `GamepadButton` | `0x1002eb68c` |
| `ControlStoryboardOption` | `0x1002ebd6c` |
| `FocusDirection` | `0x1002ec44c` |
| `MediaState` | `0x1003304a0` |

## Future Work

- Extract XAML structure from game files for UI modding
- Hook Noesis rendering for overlay injection
- Understand NoesisApp custom controls for BG3-specific UI elements

## Related Files

- `ghidra/offsets/GLOBALSTRINGTABLE.md` - Larian's string interning (different system)
- Windows BG3SE has Noesis hooks for console UI
