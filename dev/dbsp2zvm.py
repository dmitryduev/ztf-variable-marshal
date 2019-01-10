import pandas as pd
import json


if __name__ == '__main__':
    # make a fake json spectrum file for the Marshal

    data = pd.read_csv('./blue0025.spec.txt', sep="  ", header=None)
    data.columns = ['wavelength', 'flux']

    data['fluxerr'] = 0.5

    spec_data = data.to_dict(orient='records')

    sp = {"telescope": "PO:5m",
          "instrument": "DBSP",
          "filter": "V",
          "mjd": 58400.0,
          "comment": "random DBSP spectrum",
          "data": spec_data
          }

    with open('./spec_dbsp.json', 'w') as f:
        json.dump(sp, f, indent=2)
