from time import time
from math import floor
from random import randint
from hashlib import sha256
from base64 import b64encode, b64decode
from functools import reduce
from typing import List
from re import sub, compile, VERBOSE, MULTILINE
from bs4 import BeautifulSoup

from ..helpers import Cubic, MathUtils
from ..exceptions import InvalidHomePageError, InvalidOndemandFileError


class ClientTransactionGenerator:
    def __init__(self, ondemand_file: str, home_page: str):
        """
        Initialize the client transaction generator.
        
        Args:
            ondemand_file: Content of the ondemand JavaScript file
            home_page: HTML content of the Twitter home page
        """
        try:
            # Extract indices from ondemand file
            if not (indices := [
                int(m.group(2)) for m in compile(
                    r"""(\(\w{1}\[(\d{1,2})\],\s*16\))+""",
                    flags=(VERBOSE | MULTILINE)
                ).finditer(ondemand_file)
            ]):
                raise InvalidOndemandFileError("Couldn't get KEY_BYTE indices")
            self.row_index, self.key_bytes_indices = indices[0], indices[1:]
        except Exception as e:
            raise InvalidOndemandFileError(f"Couldn't get KEY_BYTE indices: {e}")

        try:
            soup = BeautifulSoup(home_page, 'html.parser')
            element = soup.select_one("meta[name='twitter-site-verification']")
            if not element:
                raise InvalidHomePageError("Couldn't get [twitter-site-verification] key")
            key = element.get("content")
            self.key_bytes = list(b64decode(key.encode()))
            self.animation_key = self._get_animation_key(soup)
        except Exception as e:
            raise InvalidHomePageError(f"Couldn't get [twitter-site-verification] key: {e}")

    def generate(self, method: str, path: str) -> str:
        """
        Generate client transaction ID for API request.
        
        Args:
            method: HTTP method (e.g., "GET", "POST")
            path: API endpoint path
        
        Returns:
            Base64-encoded client transaction ID
        """
        # Calculate current time offset
        time_now = floor((time() * 1000 - 1682924400000) / 1000)
        time_now_bytes = [(time_now >> (i * 8)) & 0xFF for i in range(4)]
        
        # Generate hash
        hash_val = sha256(
            f"{method}!{path}!{time_now}obfiowerehiring{self.animation_key}".encode()
        ).digest()
        
        # Build final byte array with XOR encoding
        random_num = randint(0, 255)
        bytes_arr = [*self.key_bytes, *time_now_bytes, *list(hash_val)[:16], 3]
        out = bytearray([random_num, *[b ^ random_num for b in bytes_arr]])
        
        return b64encode(out).decode().rstrip("=")
    

    def _get_animation_key(self, home_page_response: BeautifulSoup) -> str:
        """
        Calculate animation key from key bytes.
        
        Args:
            home_page_response: Parsed HTML soup object from home page
        
        Returns:
            Animation key string
        """
        # Calculate row index and frame time
        row_index = self.key_bytes[self.row_index] % 16
        frame_time = reduce(lambda x, y: x * y, 
                          [self.key_bytes[i] % 16 for i in self.key_bytes_indices])
        frame_time = MathUtils.round(frame_time / 10) * 10
        
        
        # Extract path data from animation frames
        frames = home_page_response.select("[id^='loading-x-anim']")
        path_data = list(list(frames[self.key_bytes[5] % 4].children)[0].children)[1].get("d")[9:]
        arr = [
            [int(x) for x in sub(r"[^\d]+", " ", item).strip().split()] 
            for item in path_data.split("C")
        ]
        
        # Animate the frame
        frame_row = arr[row_index]
        target_time = float(frame_time) / 4096
        return self._animate(frame_row, target_time)

    def _animate(self, frames: List[int], target_time: float) -> str:
        """
        Generate animation key from frame data and target time.
        
        Args:
            frames: List of frame data values
            target_time: Target time for animation interpolation
        
        Returns:
            Animation key string
        """
        # Scale value from 0-255 range to min-max range
        def solve(value, min_val, max_val, rounding):
            result = value * (max_val - min_val) / 255 + min_val
            return floor(result) if rounding else round(result, 2)
        
        # Extract color and rotation data
        from_color = [float(x) for x in [*frames[:3], 1]]
        to_color = [float(x) for x in [*frames[3:6], 1]]
        to_rotation = [solve(float(frames[6]), 60.0, 360.0, True)]
        
        # Generate cubic bezier curves and interpolate
        curves = [
            solve(float(item), MathUtils.is_odd(i), 1.0, False) 
            for i, item in enumerate(frames[7:])
        ]
        
        val = Cubic(curves).get_value(target_time)
        color = [max(0, min(255, v)) for v in MathUtils.interpolate(from_color, to_color, val)]
        rotation = MathUtils.interpolate([0.0], to_rotation, val)
        matrix = MathUtils.convert_rotation_to_matrix(rotation[0])
        
        # Build animation key string
        str_arr = [format(round(value), 'x') for value in color[:-1]]
        for value in matrix:
            rounded = abs(round(value, 2))
            hex_value = MathUtils.float_to_hex(rounded)
            str_arr.append(f"0{hex_value}".lower() if hex_value.startswith(".") else hex_value or '0')
        str_arr.extend(["0", "0"])
        
        return sub(r"[.-]", "", "".join(str_arr))
