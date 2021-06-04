import React from "react"
import PropTypes from "prop-types"
import { connect } from "react-redux"
import { ConnectionState } from "../../ducks/connection"


ConnectionIndicator.propTypes = {
    state: PropTypes.symbol.isRequired,
    message: PropTypes.string,

}
export function ConnectionIndicator({ state, message }) {
    switch (state) {
        case ConnectionState.INIT:
            return <span className="connection-indicator init badge">connecting…</span>;
        case ConnectionState.FETCHING:
            return <span className="connection-indicator fetching badge">fetching data…</span>;
        case ConnectionState.ESTABLISHED:
            return <span className="connection-indicator established badge">connected</span>;
        case ConnectionState.ERROR:
            return <span className="connection-indicator error badge"
                         title={message}>connection lost</span>;
        case ConnectionState.OFFLINE:
            return <span className="connection-indicator offline badge">offline</span>;
    }
}

export default connect(
    state => state.connection,
)(ConnectionIndicator)
