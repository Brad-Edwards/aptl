"""Named virtio channel device tests."""

from pathlib import Path

import pytest

from aptl.appliance.seat import _device


def test_character_device_writer_retries_short_writes(mocker) -> None:
    opened = mocker.patch.object(_device, "open_character_device", return_value=42)
    write = mocker.patch.object(_device.os, "write", side_effect=(2, 3))
    close = mocker.patch.object(_device.os, "close")

    _device.write_character_device(Path("/dev/virtio-ports/test"), b"abcde")

    opened.assert_called_once_with(Path("/dev/virtio-ports/test"), _device.os.O_WRONLY)
    assert bytes(write.call_args_list[0].args[1]) == b"abcde"
    assert bytes(write.call_args_list[1].args[1]) == b"cde"
    close.assert_called_once_with(42)


def test_character_device_writer_rejects_symlink_to_regular_file(
    tmp_path: Path,
) -> None:
    regular = tmp_path / "regular"
    regular.write_bytes(b"unchanged")
    channel = tmp_path / "org.aptl.readiness"
    channel.symlink_to(regular)

    with pytest.raises(OSError, match="not a character device"):
        _device.write_character_device(channel, b"payload")

    assert regular.read_bytes() == b"unchanged"
