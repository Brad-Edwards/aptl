# Deterministic ACES inventory Syft CycloneDX normalization.
# Allowed transform: remove Syft file-location component properties only.
def strip_syft_location_properties:
  walk(
    if type == "object" and has("properties") then
      .properties |= map(
        select(((.name // "") | startswith("syft:location:")) | not)
      )
      | if .properties == [] then del(.properties) else . end
    else
      .
    end
  );

strip_syft_location_properties
