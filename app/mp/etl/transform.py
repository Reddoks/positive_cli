from app.mp.api import MPAPIResponse
from quickjs import Function


class JSTransform:
    def __init__(self, code: str):
        self.function = Function("transform", code)
        self.state = {}

    # Run transform on data
    def transform(self, data, aggregated=False) -> MPAPIResponse:
        # Run JS transformer
        try:
            response, state = self.function(data, self.state)
            if state:
                self.state = state
            if aggregated:
                return state.get("aggregated")
            return response

        except BaseException as err:
            print('An exception occurred in transform function: {}'.format(err))
            return MPAPIResponse(state=False,
                                 message='An exception occurred in transform function: {}'.format(err))

