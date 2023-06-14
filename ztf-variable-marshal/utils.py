import base64
import datetime
import hashlib
import itertools
import math
import random
import secrets
import string
from string import ascii_lowercase

import bcrypt
import numpy as np
import pytz
import requests
from bson.json_util import dumps
from numba import jit


def generate_password_hash(password, salt_rounds=12):
    password_bin = password.encode("utf-8")
    hashed = bcrypt.hashpw(password_bin, bcrypt.gensalt(salt_rounds))
    encoded = base64.b64encode(hashed)
    return encoded.decode("utf-8")


def check_password_hash(encoded, password):
    password = password.encode("utf-8")
    encoded = encoded.encode("utf-8")

    hashed = base64.b64decode(encoded)
    is_correct = bcrypt.hashpw(password, hashed) == hashed
    return is_correct


def to_pretty_json(value):
    # return dumps(value, indent=4)  # , separators=(',', ': ')
    return dumps(value, separators=(",", ": "))


# @jit(forceobj=True)
def great_circle_distance(phi1, lambda1, phi2, lambda2):
    # input: dec1, ra1, dec2, ra2 [rad]
    # this is orders of magnitude faster than astropy.coordinates.Skycoord.separation
    delta_lambda = np.abs(lambda2 - lambda1)
    return np.arctan2(
        np.sqrt(
            (np.cos(phi2) * np.sin(delta_lambda)) ** 2
            + (
                np.cos(phi1) * np.sin(phi2)
                - np.sin(phi1) * np.cos(phi2) * np.cos(delta_lambda)
            )
            ** 2
        ),
        np.sin(phi1) * np.sin(phi2)
        + np.cos(phi1) * np.cos(phi2) * np.cos(delta_lambda),
    )


# @jit(forceobj=True)
def deg2hms(x):
    """Transform degrees to *hours:minutes:seconds* strings.
    Parameters
    ----------
    x : float
        The degree value c [0, 360) to be written as a sexagesimal string.
    Returns
    -------
    out : str
        The input angle written as a sexagesimal string, in the
        form, hours:minutes:seconds.
    """
    assert 0.0 <= x < 360.0, "Bad RA value in degrees"
    # ac = Angle(x, unit='degree')
    # hms = str(ac.to_string(unit='hour', sep=':', pad=True))
    # print(str(hms))
    _h = np.floor(x * 12.0 / 180.0)
    _m = np.floor((x * 12.0 / 180.0 - _h) * 60.0)
    _s = ((x * 12.0 / 180.0 - _h) * 60.0 - _m) * 60.0
    hms = "{:02.0f}:{:02.0f}:{:07.4f}".format(_h, _m, _s)
    # print(hms)
    return hms


# @jit(forceobj=True)
def deg2dms(x):
    """Transform degrees to *degrees:arcminutes:arcseconds* strings.
    Parameters
    ----------
    x : float
        The degree value c [-90, 90] to be converted.
    Returns
    -------
    out : str
        The input angle as a string, written as degrees:minutes:seconds.
    """
    assert -90.0 <= x <= 90.0, "Bad Dec value in degrees"
    # ac = Angle(x, unit='degree')
    # dms = str(ac.to_string(unit='degree', sep=':', pad=True))
    # print(dms)
    _d = np.floor(abs(x)) * np.sign(x)
    _m = np.floor(np.abs(x - _d) * 60.0)
    _s = np.abs(np.abs(x - _d) * 60.0 - _m) * 60.0
    dms = "{:02.0f}:{:02.0f}:{:06.3f}".format(_d, _m, _s)
    # print(dms)
    return dms


def radec_str2rad(_ra_str, _dec_str):
    """
    :param _ra_str: 'H:M:S'
    :param _dec_str: 'D:M:S'
    :return: ra, dec in rad
    """
    # convert to rad:
    _ra = list(map(float, _ra_str.split(":")))
    _ra = (_ra[0] + _ra[1] / 60.0 + _ra[2] / 3600.0) * np.pi / 12.0
    _dec = list(map(float, _dec_str.split(":")))
    _sign = -1 if _dec_str.strip()[0] == "-" else 1
    _dec = (
        _sign
        * (abs(_dec[0]) + abs(_dec[1]) / 60.0 + abs(_dec[2]) / 3600.0)
        * np.pi
        / 180.0
    )

    return _ra, _dec


def radec_str2deg(_ra_str, _dec_str):
    """
    :param _ra_str: 'H:M:S'
    :param _dec_str: 'D:M:S'
    :return: ra, dec in deg
    """
    # convert to rad:
    _ra = list(map(float, _ra_str.split(":")))
    _ra = _ra[0] + _ra[1] / 60.0 + _ra[2] / 3600.0
    _dec = list(map(float, _dec_str.split(":")))
    _sign = -1 if _dec_str.strip()[0] == "-" else 1
    _dec = _sign * (abs(_dec[0]) + abs(_dec[1]) / 60.0 + abs(_dec[2]) / 3600.0)

    return _ra, _dec


def radec_str2geojson(ra_str, dec_str):

    # hms -> ::, dms -> ::
    if isinstance(ra_str, str) and isinstance(dec_str, str):
        if ("h" in ra_str) and ("m" in ra_str) and ("s" in ra_str):
            ra_str = ra_str[:-1]  # strip 's' at the end
            for char in ("h", "m"):
                ra_str = ra_str.replace(char, ":")
        if ("d" in dec_str) and ("m" in dec_str) and ("s" in dec_str):
            dec_str = dec_str[:-1]  # strip 's' at the end
            for char in ("d", "m"):
                dec_str = dec_str.replace(char, ":")

        if (":" in ra_str) and (":" in dec_str):
            ra, dec = radec_str2rad(ra_str, dec_str)
            # convert to geojson-friendly degrees:
            ra = ra * 180.0 / np.pi - 180.0
            dec = dec * 180.0 / np.pi
        else:
            raise Exception("Unrecognized string ra/dec format.")
    else:
        # already in degrees?
        ra = float(ra_str)
        # geojson-friendly ra:
        ra -= 180.0
        dec = float(dec_str)

    return ra, dec


def parse_radec(ra, dec):
    try:
        if isinstance(ra, str) and isinstance(dec, str):
            if ("h" in ra) and ("m" in ra) and ("s" in ra):
                ra = ra[:-1]  # strip 's' at the end
                for char in ("h", "m"):
                    ra = ra.replace(char, ":")
            if ("d" in dec) and ("m" in dec) and ("s" in dec):
                dec = dec[:-1]  # strip 's' at the end
                for char in ("d", "m"):
                    dec = dec.replace(char, ":")

            if (":" in ra) and (":" in dec):
                # convert to rad:
                ra, dec = radec_str2rad(ra, dec)
                # convert to geojson-friendly degrees:
                ra = ra * 180.0 / np.pi
                dec = dec * 180.0 / np.pi

            else:
                # must be degrees then
                ra = float(ra)
                dec = float(dec)
        else:
            # must be degrees then
            ra = float(ra)
            dec = float(dec)

        radec = {
            "ra": ra,
            "dec": dec,
            "coordinates": {
                "radec_str": [deg2hms(ra), deg2dms(dec)],
                "radec_geojson": {"type": "Point", "coordinates": [ra - 180.0, dec]},
            },
        }
    except Exception as e:
        raise Exception(f"Unrecognized string ra/dec format.: {e}")

    return radec


def utc_now():
    return datetime.datetime.now(pytz.utc)


def jd(_t):
    """
    Calculate Julian Date
    """
    assert isinstance(
        _t, datetime.datetime
    ), "function argument must be a datetime.datetime instance"

    a = np.floor((14 - _t.month) / 12)
    y = _t.year + 4800 - a
    m = _t.month + 12 * a - 3

    jdn = (
        _t.day
        + np.floor((153 * m + 2) / 5.0)
        + 365 * y
        + np.floor(y / 4.0)
        - np.floor(y / 100.0)
        + np.floor(y / 400.0)
        - 32045
    )

    _jd = (
        jdn
        + (_t.hour - 12.0) / 24.0
        + _t.minute / 1440.0
        + _t.second / 86400.0
        + _t.microsecond / 86400000000.0
    )

    return _jd


def mjd(_t):
    """
    Calculate Modified Julian Date
    """
    assert isinstance(
        _t, datetime.datetime
    ), "function argument must be a datetime.datetime instance"
    _jd = jd(_t)
    _mjd = _jd - 2400000.5
    return _mjd


def days_to_hmsm(days):
    """
    Convert fractional days to hours, minutes, seconds, and microseconds.
    Precision beyond microseconds is rounded to the nearest microsecond.

    Parameters
    ----------
    days : float
        A fractional number of days. Must be less than 1.

    Returns
    -------
    hour : int
        Hour number.

    min : int
        Minute number.

    sec : int
        Second number.

    micro : int
        Microsecond number.

    Raises
    ------
    ValueError
        If `days` is >= 1.

    Examples
    --------
    >>> days_to_hmsm(0.1)
    (2, 24, 0, 0)

    """
    hours = days * 24.0
    hours, hour = math.modf(hours)

    mins = hours * 60.0
    mins, min = math.modf(mins)

    secs = mins * 60.0
    secs, sec = math.modf(secs)

    micro = round(secs * 1.0e6)

    return int(hour), int(min), int(sec), int(micro)


def jd_to_date(jd):
    """
    Convert Julian Day to date.

    Algorithm from 'Practical Astronomy with your Calculator or Spreadsheet',
        4th ed., Duffet-Smith and Zwart, 2011.

    Parameters
    ----------
    jd : float
        Julian Day

    Returns
    -------
    year : int
        Year as integer. Years preceding 1 A.D. should be 0 or negative.
        The year before 1 A.D. is 0, 10 B.C. is year -9.

    month : int
        Month as integer, Jan = 1, Feb. = 2, etc.

    day : float
        Day, may contain fractional part.

    Examples
    --------
    Convert Julian Day 2446113.75 to year, month, and day.

    >>> jd_to_date(2446113.75)
    (1985, 2, 17.25)

    """
    jd = jd + 0.5

    FRACTIONAL_PART, INT_PART = math.modf(jd)
    INT_PART = int(INT_PART)

    A = math.trunc((INT_PART - 1867216.25) / 36524.25)

    if INT_PART > 2299160:
        B = INT_PART + 1 + A - math.trunc(A / 4.0)
    else:
        B = INT_PART

    C = B + 1524

    D = math.trunc((C - 122.1) / 365.25)

    E = math.trunc(365.25 * D)

    G = math.trunc((C - E) / 30.6001)

    day = C - E + FRACTIONAL_PART - math.trunc(30.6001 * G)

    if G < 13.5:
        month = G - 1
    else:
        month = G - 13

    if month > 2.5:
        year = D - 4716
    else:
        year = D - 4715

    return year, month, day


def jd_to_datetime(_jd):
    """
    Convert a Julian Day to an `jdutil.datetime` object.

    Parameters
    ----------
    jd : float
        Julian day.

    Returns
    -------
    dt : `jdutil.datetime` object
        `jdutil.datetime` equivalent of Julian day.

    Examples
    --------
    >>> jd_to_datetime(2446113.75)
    datetime(1985, 2, 17, 6, 0)

    """
    year, month, day = jd_to_date(_jd)

    frac_days, day = math.modf(day)
    day = int(day)

    hour, min_, sec, micro = days_to_hmsm(frac_days)

    return datetime.datetime(year, month, day, hour, min_, sec, micro)


def mjd_to_datetime(_mjd):
    _jd = _mjd + 2400000.5

    return jd_to_datetime(_jd)


def compute_hash(_task):
    """
        Compute hash for a hashable task
    :return:
    """
    ht = hashlib.blake2b(digest_size=16)
    ht.update(_task.encode("utf-8"))
    hsh = ht.hexdigest()

    return hsh


def random_alphanumeric_str(length: int = 8):
    return "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(length)
    ).lower()


@jit(forceobj=True)
def iter_all_strings():
    for size in itertools.count(1):
        for s in itertools.product(ascii_lowercase, repeat=size):
            yield "".join(s)


def num2alphabet(num: int):

    assert num >= 1, "bad number"

    for s in itertools.islice(iter_all_strings(), num):
        pass

    return s


def alphabet2num(dg: str):
    return sum(
        (
            (ord(dg[x]) - ord("a") + 1) * (26 ** (len(dg) - x - 1))
            for x in range(0, len(dg))
        )
    )


# alphabet = string.ascii_letters + string.digits
alphabet = string.ascii_lowercase + string.digits


def uid(prefix: str = "", length: int = 6):
    return prefix + "".join(secrets.choice(alphabet) for _ in range(length))


# Rotation matrix for the conversion : x_galactic = R * x_equatorial (J2000)
# http://adsabs.harvard.edu/abs/1989A&A...218..325M
RGE = np.array(
    [
        [-0.054875539, -0.873437105, -0.483834992],
        [+0.494109454, -0.444829594, +0.746982249],
        [-0.867666136, -0.198076390, +0.455983795],
    ]
)


def radec2lb(ra, dec):
    """
    ra [deg]
    dec [deg]

    return l [deg], b [deg]
    """
    ra_rad, dec_rad = np.deg2rad(ra), np.deg2rad(dec)
    u = np.array(
        [
            np.cos(ra_rad) * np.cos(dec_rad),
            np.sin(ra_rad) * np.cos(dec_rad),
            np.sin(dec_rad),
        ]
    )

    ug = np.dot(RGE, u)

    x, y, z = ug
    gal_l = np.arctan2(y, x)
    gal_b = np.arctan2(z, (x * x + y * y) ** 0.5)
    return np.rad2deg(gal_l), np.rad2deg(gal_b)


colors = {
    1: ["#28a745", "#043927", "#0b6623", "#4F7942", "#4CBB17", "#006E51", "#79C753"],
    2: ["#dc3545", "#8d021f", "#FF0800", "#ff2800", "#960018", "#FF2400", "#7C0A02"],
    3: ["#343a40", "#343434", "#36454F", "#909090", "#536267", "#4C5866", "#9896A4"],
    "zg": ["#28a745", "#0b6623", "#043927", "#4F7942", "#4CBB17", "#006E51", "#79C753"],
    "zr": ["#dc3545", "#8d021f", "#960018", "#ff2800", "#FF0800", "#FF2400", "#7C0A02"],
    "zi": ["#343a40", "#343434", "#36454F", "#909090", "#536267", "#4C5866", "#9896A4"],
    "g": ["#28a745", "#0b6623", "#043927", "#4F7942", "#4CBB17", "#006E51", "#79C753"],
    "r": ["#dc3545", "#8d021f", "#960018", "#ff2800", "#FF0800", "#FF2400", "#7C0A02"],
    "i": ["#343a40", "#343434", "#36454F", "#909090", "#536267", "#4C5866", "#9896A4"],
    "default": ["#00415a", "#005960", "#20208b", "#00265e", "#00325e", "#00325e"],
}


def lc_colors(color="default", ind: int = 0):
    if color in colors:
        # re-use if ran out of available colors:
        return colors[color][ind % len(colors[color])]
    else:
        return colors["default"][ind % len(colors["default"])]


# PS1 cutouts from Mickael Rigault's ztfquery
# https://github.com/MickaelRigault/ztfquery/blob/master/ztfquery/utils/stamps.py

PANSTARRS_SOURCE = "http://ps1images.stsci.edu/cgi-bin/"

# ===================== #
#   Internal Tools      #
# ===================== #


def build_panstarrs_link(ra, dec, type="stack"):
    """build the link where you will get the ps1 filename information for the given Ra Dec and type."""
    return (
        PANSTARRS_SOURCE
        + "ps1filenames.py?ra="
        + str(ra)
        + "&dec="
        + str(dec)
        + "&type=%s" % type
    )


def get_ps_color_filelocation(ra, dec, color=("y", "g", "i"), timeout=1):
    """ """
    if len(color) != 3:
        raise ValueError("color must have exactly 3 entries ('g','r','i','z','y')")
    d = [
        link.split(" ")[-2]
        for link in requests.get(build_panstarrs_link(ra, dec), timeout=timeout)
        .content.decode("utf-8")
        .splitlines()[1:]
    ]
    return np.asarray([[d_ for d_ in d if ".%s." % b in d_] for b in color]).flatten()


def get_rgb_ps_stamp_url(ra, dec, size=240, color=("y", "g", "i"), timeout=1):
    """build the link url where you can download the RGB stamps centered on RA-Dec with a `size`.
    The RGB color is based on the given color [R,G,B] you set in.

    Returns
    -------
    link (str)
    """
    red, blue, green = get_ps_color_filelocation(ra, dec, color=color, timeout=timeout)
    return (
        PANSTARRS_SOURCE
        + "fitscut.cgi?red="
        + red
        + "&blue="
        + blue
        + "&green="
        + green
        + "&x="
        + str(ra)
        + "&y="
        + str(dec)
        + "&size=%d" % size
        + "&wcs=1&asinh=True&autoscale=99.750000&format=png&download=True"
    )
