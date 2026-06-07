walk(
  if type == "object" then
    if has("properties") then
      .properties |= map(select(.name | startswith("syft:location:") | not))
      | if (.properties | length) == 0 then del(.properties) else . end
    else
      .
    end
  else
    .
  end
)
