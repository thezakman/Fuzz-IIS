from . import __version__

AUTHOR = "TheZakMan"

BANNER = rf'''
   .....
 .H8888888x.  '`+
:888888888888x.  !
8~    `"*88888888"
!      .  `f""""   ?88   d8P  d88888P  d88888P
 ~:...-` :8L <)88: d88   88      d8P'     d8P'
    .   :888:>X88! ?8b  ,88    d8P'     d8P'
 :~"88x 48888X ^`  `?88P'?8  bd88888P' d88888P'
<  :888k'88888X  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  d8888f '88888X  ▗▄▄▄▖▗▄▄▄▖ ▗▄▄▖
 :8888!    ?8888>   ▓    ▓  ▐▌    ╶Internet
 X888!      8888~   ▒    ▒   ▝▀▚▖ ╶Information
 '888       X88f   ▄█▄▖▗▄█▄▖▗▄▄▞▘ ╶Services
  '%8:     .8*"  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
     ^----~"`     ▔▔Done by:▔{AUTHOR}▔▔v{__version__}▔

        "talk is cheap, show me the bug"
     '''


def print_banner(console) -> None:
    console.print(BANNER, style="bright_white", highlight=False)
