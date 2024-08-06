import regularReducer, {
    getSpecs,
    initialState,
    setListenHost,
    setListenPort,
    setActive,
} from "./../../../ducks/modes/regular";
import { ModesState } from "../../../ducks/modes";
import * as backendState from "../../../ducks/backendState";
import { TStore } from "../tutils";
import fetchMock, { enableFetchMocks } from "jest-fetch-mock";

describe("regularReducer", () => {
    it("should dispatch MODE_REGULAR_TOGGLE and updateMode", async () => {
        enableFetchMocks();

        const store = TStore();

        expect(store.getState().modes.regular.active).toBe(true);
        await store.dispatch(setActive(false));
        expect(store.getState().modes.regular.active).toBe(false);
        expect(fetchMock).toHaveBeenCalled();
    });

    it("should dispatch MODE_REGULAR_SET_PORT and updateMode", async () => {
        enableFetchMocks();
        const store = TStore();

        await store.dispatch(setListenPort(8082));

        const state = store.getState().modes.regular;
        expect(state.listen_port).toBe(8082);
        expect(fetchMock).toHaveBeenCalled();
    });

    it("should dispatch MODE_REGULAR_SET_HOST and updateMode", async () => {
        enableFetchMocks();
        const store = TStore();

        await store.dispatch(setListenHost("localhost"));

        const state = store.getState().modes.regular;
        expect(state.listen_host).toBe("localhost");
        expect(fetchMock).toHaveBeenCalled();
    });

    it('should handle RECEIVE_STATE action with data.servers containing "regular", an host and a port', () => {
        const action = {
            type: backendState.RECEIVE,
            data: {
                servers: [
                    {
                        description: "HTTP(S) proxy",
                        full_spec: "regular@localhost:8081",
                        is_running: true,
                        last_exception: null,
                        listen_addrs: [
                            ["127.0.0.1", 8081],
                            ["::1", 8081],
                        ],
                        type: "regular",
                    },
                ],
            },
        };
        const newState = regularReducer(initialState, action);
        expect(newState.active).toBe(true);
        expect(newState.listen_host).toBe("localhost");
        expect(newState.listen_port).toBe(8081);
    });

    it('should handle RECEIVE_STATE action with data.servers containing just "regular"', () => {
        const initialState = {
            active: false,
            listen_host: "localhost",
            listen_port: 8080,
        };
        const action = {
            type: backendState.RECEIVE,
            data: {
                servers: [
                    {
                        description: "HTTP(S) proxy",
                        full_spec: "regular",
                        is_running: true,
                        last_exception: null,
                        listen_addrs: [
                            ["::", 8080, 0, 0],
                            ["0.0.0.0", 8080],
                        ],
                        type: "regular",
                    },
                ],
            },
        };
        const newState = regularReducer(initialState, action);
        expect(newState.active).toBe(true);
        expect(newState.listen_host).toBe(undefined);
        expect(newState.listen_port).toBe(undefined);
    });

    it("should handle RECEIVE_STATE action with data.servers containing another mode", () => {
        const initialState = {
            active: false,
            listen_host: "localhost",
            listen_port: 8080,
        };
        const action = {
            type: backendState.RECEIVE,
            data: {
                servers: [
                    {
                        description: "Local redirector",
                        full_spec: "local",
                        is_running: true,
                        last_exception: null,
                        listen_addrs: [],
                        type: "local",
                    },
                ],
            },
        };
        const newState = regularReducer(initialState, action);
        expect(newState.active).toBe(false);
        expect(newState.listen_host).toBe(initialState.listen_host);
        expect(newState.listen_port).toBe(initialState.listen_port);
    });

    it("should handle RECEIVE_STATE action without data.servers", () => {
        const initialState = {
            active: false,
            listen_host: "localhost",
            listen_port: 8080,
        };
        const action = {
            type: backendState.RECEIVE,
            data: {},
        };
        const newState = regularReducer(initialState, action);
        expect(newState.active).toBe(initialState.active);
        expect(newState.listen_host).toBe(initialState.listen_host);
        expect(newState.listen_port).toBe(initialState.listen_port);
    });

    it("should handle error when toggling regular", async () => {
        fetchMock.mockReject(new Error("invalid spec"));
        const store = TStore();

        await store.dispatch(setActive(false));

        expect(fetchMock).toHaveBeenCalled();
        expect(store.getState().modes.regular.error).toBe("invalid spec");
    });

    it("should handle error when setting port", async () => {
        fetchMock.mockReject(new Error("invalid spec"));
        const store = TStore();

        await store.dispatch(setListenPort(8082));

        expect(fetchMock).toHaveBeenCalled();
        expect(store.getState().modes.regular.error).toBe("invalid spec");
    });

    it("should handle error when setting host", async () => {
        fetchMock.mockReject(new Error("invalid spec"));
        const store = TStore();

        await store.dispatch(setListenHost("localhost"));

        expect(fetchMock).toHaveBeenCalled();
        expect(store.getState().modes.regular.error).toBe("invalid spec");
    });
});

describe("getMode", () => {
    it("should return the correct mode string when active", () => {
        const modes = {
            regular: {
                active: true,
            },
        } as ModesState;
        const mode = getSpecs(modes);
        expect(JSON.stringify(mode)).toBe(JSON.stringify(["regular"]));
    });

    it("should return an empty string when not active", () => {
        const modes = {
            regular: {
                active: false,
                listen_host: "localhost",
                listen_port: 8080,
            },
        } as ModesState;
        const mode = getSpecs(modes);
        expect(JSON.stringify(mode)).toBe(JSON.stringify([]));
    });
});
