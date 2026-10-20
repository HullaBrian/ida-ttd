// icons.hh: embedded Microsoft "codicon" debugger glyphs (SVG, CC BY 4.0)
// and Google Material Symbols (Apache 2.0), both credited in
// THIRD-PARTY-NOTICES.txt,
// used to give the TTD debug-movement actions clean, consistent icons.
//
// IDA's load_custom_icon() accepts SVG data ("svg" format) because the bundled
// Qt ships the SVG image plugin. Each icon is the raw SVG markup; pass it with
// its byte length (sizeof(...) - 1, excluding the terminating NUL).
#pragma once

namespace idattd
{
    // Continue / run forward
    static const char icon_continue_svg[] =
        R"SVG(<svg width="16" height="16" viewBox="0 0 16 16" fill="#1DCC23" xmlns="http://www.w3.org/2000/svg"><path d="M14.578 7.149L7.578 2.186C7.397 2.058 7.198 2 7.003 2C6.484 2 6 2.411 6 3.002V13.003C6 13.594 6.485 14.005 7.004 14.005C7.201 14.005 7.403 13.946 7.585 13.815L14.585 8.777C15.142 8.376 15.139 7.546 14.579 7.15L14.578 7.149ZM7.5 12.027V3.969L13.14 7.968L7.5 12.027ZM3.5 2.75V13.25C3.5 13.664 3.164 14 2.75 14C2.336 14 2 13.664 2 13.25V2.75C2 2.336 2.336 2 2.75 2C3.164 2 3.5 2.336 3.5 2.75Z"/></svg>)SVG";

    // Reverse continue / run backward
    static const char icon_reverse_continue_svg[] =
        R"SVG(<svg width="16" height="16" viewBox="0 0 16 16" fill="#3A9BE8" xmlns="http://www.w3.org/2000/svg"><path d="M8.99688 2C8.80188 2 8.60288 2.058 8.42188 2.186L1.42188 7.149C0.861882 7.546 0.858882 8.376 1.41588 8.776L8.41588 13.814C8.59788 13.945 8.79988 14.004 8.99688 14.004C9.51588 14.004 10.0009 13.593 10.0009 13.002V3.002C10.0009 2.412 9.51688 2 8.99788 2H8.99688ZM8.49988 12.027L2.85988 7.968L8.49988 3.969V12.027ZM13.9999 2.75V13.25C13.9999 13.664 13.6639 14 13.2499 14C12.8359 14 12.4999 13.664 12.4999 13.25V2.75C12.4999 2.336 12.8359 2 13.2499 2C13.6639 2 13.9999 2.336 13.9999 2.75Z"/></svg>)SVG";

    // Step into backwards (single backward step)
    static const char icon_step_back_svg[] =
        R"SVG(<svg width="16" height="16" viewBox="0 0 16 16" fill="#3A9BE8" xmlns="http://www.w3.org/2000/svg"><path d="M8 11C6.897 11 6 11.897 6 13C6 14.103 6.897 15 8 15C9.103 15 10 14.103 10 13C10 11.897 9.103 11 8 11ZM13.939 7.144C13.52 4.211 10.966 2 8 2C6.24 2 4.617 2.758 3.5 4.027V2.75C3.5 2.336 3.164 2 2.75 2C2.336 2 2 2.336 2 2.75V6.25C2 6.664 2.336 7 2.75 7H6.25C6.664 7 7 6.664 7 6.25C7 5.836 6.664 5.5 6.25 5.5H4.257C5.081 4.263 6.471 3.5 8 3.5C10.225 3.5 12.14 5.158 12.454 7.356C12.508 7.73 12.829 8 13.196 8C13.231 8 13.267 7.998 13.303 7.992C13.713 7.933 13.998 7.554 13.94 7.143L13.939 7.144Z"/></svg>)SVG";

    // Step into
    static const char icon_step_into_svg[] =
        R"SVG(<svg width="16" height="16" viewBox="0 0 16 16" fill="#1DCC23" xmlns="http://www.w3.org/2000/svg"><path d="M10 13C10 14.103 9.10304 15 8.00004 15C6.89704 15 6.00004 14.103 6.00004 13C6.00004 11.897 6.89704 11 8.00004 11C9.10304 11 10 11.897 10 13ZM12.03 5.22C11.737 4.927 11.262 4.927 10.969 5.22L8.74904 7.44V1.75C8.74904 1.336 8.41304 1 7.99904 1C7.58504 1 7.24904 1.336 7.24904 1.75V7.439L5.02904 5.219C4.73604 4.926 4.26104 4.926 3.96804 5.219C3.67504 5.512 3.67504 5.987 3.96804 6.28L7.46804 9.78C7.61404 9.926 7.80604 10 7.99804 10C8.19004 10 8.38204 9.927 8.52804 9.78L12.028 6.28C12.321 5.987 12.321 5.512 12.028 5.219L12.03 5.22Z"/></svg>)SVG";

    // Step over
    static const char icon_step_over_svg[] =
        R"SVG(<svg width="16" height="16" viewBox="0 0 16 16" fill="#1DCC23" xmlns="http://www.w3.org/2000/svg"><path d="M9.99993 13C9.99993 14.103 9.10293 15 7.99993 15C6.89693 15 5.99993 14.103 5.99993 13C5.99993 11.897 6.89693 11 7.99993 11C9.10293 11 9.99993 11.897 9.99993 13ZM13.2499 2C12.8359 2 12.4999 2.336 12.4999 2.75V4.027C11.3829 2.759 9.75993 2 7.99993 2C5.03293 2 2.47993 4.211 2.06093 7.144C2.00193 7.554 2.28793 7.934 2.69793 7.993C2.73393 7.999 2.76993 8.001 2.80493 8.001C3.17193 8.001 3.49293 7.731 3.54693 7.357C3.86093 5.159 5.77593 3.501 8.00093 3.501C9.52993 3.501 10.9199 4.264 11.7439 5.501H9.75093C9.33693 5.501 9.00093 5.837 9.00093 6.251C9.00093 6.665 9.33693 7.001 9.75093 7.001H13.2509C13.6649 7.001 14.0009 6.665 14.0009 6.251V2.751C14.0009 2.337 13.6649 2.001 13.2509 2.001L13.2499 2Z"/></svg>)SVG";

    // Step out / run until return
    static const char icon_step_out_svg[] =
        R"SVG(<svg width="16" height="16" viewBox="0 0 16 16" fill="#1DCC23" xmlns="http://www.w3.org/2000/svg"><path d="M9.99802 13C9.99802 14.103 9.10102 15 7.99802 15C6.89502 15 5.99802 14.103 5.99802 13C5.99802 11.897 6.89502 11 7.99802 11C9.10102 11 9.99802 11.897 9.99802 13ZM12.03 4.71999L8.53002 1.21999C8.23702 0.926994 7.76202 0.926994 7.46902 1.21999L3.96902 4.71999C3.67602 5.01299 3.67602 5.48799 3.96902 5.78099C4.26202 6.07399 4.73702 6.07399 5.03002 5.78099L7.25002 3.56099V9.24999C7.25002 9.66399 7.58602 9.99999 8.00002 9.99999C8.41402 9.99999 8.75002 9.66399 8.75002 9.24999V3.56099L10.97 5.78099C11.116 5.92699 11.308 6.00099 11.5 6.00099C11.692 6.00099 11.884 5.92799 12.03 5.78099C12.323 5.48799 12.323 5.01299 12.03 4.71999Z"/></svg>)SVG";

    // Step into backwards: the forward step-into glyph flipped vertically, in
    // backward blue (so the arrow points up out of the dot).
    static const char icon_step_into_back_svg[] =
        R"SVG(<svg width="16" height="16" viewBox="0 0 16 16" fill="#3A9BE8" xmlns="http://www.w3.org/2000/svg"><g transform="translate(0,16) scale(1,-1)"><path d="M10 13C10 14.103 9.10304 15 8.00004 15C6.89704 15 6.00004 14.103 6.00004 13C6.00004 11.897 6.89704 11 8.00004 11C9.10304 11 10 11.897 10 13ZM12.03 5.22C11.737 4.927 11.262 4.927 10.969 5.22L8.74904 7.44V1.75C8.74904 1.336 8.41304 1 7.99904 1C7.58504 1 7.24904 1.336 7.24904 1.75V7.439L5.02904 5.219C4.73604 4.926 4.26104 4.926 3.96804 5.219C3.67504 5.512 3.67504 5.987 3.96804 6.28L7.46804 9.78C7.61404 9.926 7.80604 10 7.99804 10C8.19004 10 8.38204 9.927 8.52804 9.78L12.028 6.28C12.321 5.987 12.321 5.512 12.028 5.219L12.03 5.22Z"/></g></svg>)SVG";

    // Step out backwards: the forward step-out glyph in backward blue
    static const char icon_step_out_back_svg[] =
        R"SVG(<svg width="16" height="16" viewBox="0 0 16 16" fill="#3A9BE8" xmlns="http://www.w3.org/2000/svg"><path d="M9.99802 13C9.99802 14.103 9.10102 15 7.99802 15C6.89502 15 5.99802 14.103 5.99802 13C5.99802 11.897 6.89502 11 7.99802 11C9.10102 11 9.99802 11.897 9.99802 13ZM12.03 4.71999L8.53002 1.21999C8.23702 0.926994 7.76202 0.926994 7.46902 1.21999L3.96902 4.71999C3.67602 5.01299 3.67602 5.48799 3.96902 5.78099C4.26202 6.07399 4.73702 6.07399 5.03002 5.78099L7.25002 3.56099V9.24999C7.25002 9.66399 7.58602 9.99999 8.00002 9.99999C8.41402 9.99999 8.75002 9.66399 8.75002 9.24999V3.56099L10.97 5.78099C11.116 5.92699 11.308 6.00099 11.5 6.00099C11.692 6.00099 11.884 5.92799 12.03 5.78099C12.323 5.48799 12.323 5.01299 12.03 4.71999Z"/></svg>)SVG";

    // Step to cursor forward
    static const char icon_step_to_cursor_forward_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#1DCC23" xmlns="http://www.w3.org/2000/svg"><path d="M760-160v-640h80v640h-80ZM480-280l-56-56 104-104H120v-80h408L424-624l56-56 200 200-200 200Z"/></svg>)SVG";

    // Step to cursor backward: the forward run-to-cursor glyph mirrored, in
    // backward blue (the previous markup here duplicated the go-to-position clock).
    static const char icon_step_to_cursor_backward_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#3A9BE8" xmlns="http://www.w3.org/2000/svg"><g transform="translate(960,0) scale(-1,1)"><path d="M760-160v-640h80v640h-80ZM480-280l-56-56 104-104H120v-80h408L424-624l56-56 200 200-200 200Z"/></g></svg>)SVG";

    // TTD timeline
    static const char icons_timeline_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M120-240q-33 0-56.5-23.5T40-320q0-33 23.5-56.5T120-400h10.5q4.5 0 9.5 2l182-182q-2-5-2-9.5V-600q0-33 23.5-56.5T400-680q33 0 56.5 23.5T480-600q0 2-2 20l102 102q5-2 9.5-2h21q4.5 0 9.5 2l142-142q-2-5-2-9.5V-640q0-33 23.5-56.5T840-720q33 0 56.5 23.5T920-640q0 33-23.5 56.5T840-560h-10.5q-4.5 0-9.5-2L678-420q2 5 2 9.5v10.5q0 33-23.5 56.5T600-320q-33 0-56.5-23.5T520-400v-10.5q0-4.5 2-9.5L420-522q-5 2-9.5 2H400q-2 0-20-2L198-340q2 5 2 9.5v10.5q0 33-23.5 56.5T120-240Z"/></svg>)SVG";

    // Find calls by name/pattern (Material Symbols 'function_search')
    static const char icons_function_search_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M181-120q-45 0-73-24t-28-64q0-32 17-51.5t43-19.5q25 0 42.5 17t17.5 41q0 5-.5 9t-1.5 9q5-1 8.5-5.5T212-221l62-339H160v-80h129l21-114q7-38 37.5-62t72.5-24q44 0 72 26t28 65q0 30-17 49.5T460-680q-25 0-42.5-17T400-739q0-5 .5-9t1.5-9q-6 2-9 6t-5 12l-17 99h189v80H356l-64 344q-8 45-37 70.5T181-120Zm643 40L716-188q-22 13-46 20.5t-50 7.5q-75 0-127.5-52.5T440-340q0-75 52.5-127.5T620-520q75 0 127.5 52.5T800-340q0 26-7.5 50T772-244l108 108-56 56ZM691-269q29-29 29-71t-29-71q-29-29-71-29t-71 29q-29 29-29 71t29 71q29 29 71 29t71-29Z"/></svg>)SVG";

    // Bookmark the current position (a bookmark with a plus)
    static const char icons_bookmark_add_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#E5342C" xmlns="http://www.w3.org/2000/svg"><path d="M200-120v-640q0-33 23.5-56.5T280-840h240v80H280v518l200-86 200 86v-278h80v400L480-240 200-120Zm480-560v-80h-80v-80h80v-80h80v80h80v80h-80v80h-80Z"/></svg>)SVG";

    // The saved bookmarks for this database
    static const char icons_bookmarks_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#E5342C" xmlns="http://www.w3.org/2000/svg"><path d="M120-40v-600q0-33 23.5-56.5T200-720h280q33 0 56.5 23.5T560-640v600L340-134 120-40Zm80-122 140-60 140 60v-478H200v478Zm600-38v-680H280v-80h520q33 0 56.5 23.5T880-880v680h-80Z"/></svg>)SVG";

    // Go to position by timestamp
    static const char icons_goto_time_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M600-160q-134 0-227-93t-93-227q0-133 93-226.5T600-800q133 0 226.5 93.5T920-480q0 134-93.5 227T600-160Zm0-80q100 0 170-70t70-170q0-100-70-170t-170-70q-100 0-170 70t-70 170q0 100 70 170t170 70Zm91-91 57-57-108-108v-144h-80v177l131 132ZM80-600v-80h160v80H80ZM40-440v-80h200v80H40Zm40 160v-80h160v80H80Zm520-200Z"/></svg>)SVG";

    // Find all calls to this function (Material Symbols 'function')
    static const char icons_function_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M400-240v-80h62l105-120-105-120h-66l-64 344q-8 45-37 70.5T221-120q-45 0-73-24t-28-64q0-32 17-51.5t43-19.5q25 0 42.5 17t17.5 41q0 5-.5 9t-1.5 9q5-1 8.5-5.5T252-221l62-339H200v-80h129l21-114q7-38 37.5-62t72.5-24q44 0 72 26t28 65q0 30-17 49.5T500-680q-25 0-42.5-17T440-739q0-5 .5-9t1.5-9q-6 2-9 6t-5 12l-17 99h189v80h-32l52 59 52-59h-32v-80h200v80h-62L673-440l105 120h62v80H640v-80h32l-52-60-52 60h32v80H400Z"/></svg>)SVG";

    // Call tree (Material Symbols 'account_tree')
    static const char icons_call_tree_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M600-120v-120H440v-400h-80v120H80v-320h280v120h240v-120h280v320H600v-120h-80v320h80v-120h280v320H600ZM160-760v160-160Zm520 400v160-160Zm0-400v160-160Zm0 160h120v-160H680v160Zm0 400h120v-160H680v160ZM160-600h120v-160H160v160Z"/></svg>)SVG";

    // Find memory accesses (Material Symbols 'memory', a chip)
    static const char icons_memory_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M360-360v-240h240v240H360Zm80-80h80v-80h-80v80Zm-80 320v-80h-80q-33 0-56.5-23.5T200-280v-80h-80v-80h80v-80h-80v-80h80v-80q0-33 23.5-56.5T280-760h80v-80h80v80h80v-80h80v80h80q33 0 56.5 23.5T760-680v80h80v80h-80v80h80v80h-80v80q0 33-23.5 56.5T680-200h-80v80h-80v-80h-80v80h-80Zm320-160v-400H280v400h400ZM480-480Z"/></svg>)SVG";

    // Material Symbols "terminal" (Syscalls)
    static const char icons_syscalls_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M160-160q-33 0-56.5-23.5T80-240v-480q0-33 23.5-56.5T160-800h640q33 0 56.5 23.5T880-720v480q0 33-23.5 56.5T800-160H160Zm0-80h640v-400H160v400Zm140-40-56-56 103-104-104-104 57-56 160 160-160 160Zm180 0v-80h240v80H480Z"/></svg>)SVG";

    // Material Symbols "conversion_path" (Where did this value come from?)
    static const char icons_origin_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M760-120q-39 0-70-22.5T647-200H440q-66 0-113-47t-47-113q0-66 47-113t113-47h80q33 0 56.5-23.5T600-600q0-33-23.5-56.5T520-680H313q-13 35-43.5 57.5T200-600q-50 0-85-35t-35-85q0-50 35-85t85-35q39 0 69.5 22.5T313-760h207q66 0 113 47t47 113q0 66-47 113t-113 47h-80q-33 0-56.5 23.5T360-360q0 33 23.5 56.5T440-280h207q13-35 43.5-57.5T760-360q50 0 85 35t35 85q0 50-35 85t-85 35ZM228.5-691.5Q240-703 240-720t-11.5-28.5Q217-760 200-760t-28.5 11.5Q160-737 160-720t11.5 28.5Q183-680 200-680t28.5-11.5Z"/></svg>)SVG";

    // Material Symbols "link" (Handles)
    static const char icons_handles_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M440-280H280q-83 0-141.5-58.5T80-480q0-83 58.5-141.5T280-680h160v80H280q-50 0-85 35t-35 85q0 50 35 85t85 35h160v80ZM320-440v-80h320v80H320Zm200 160v-80h160q50 0 85-35t35-85q0-50-35-85t-85-35H520v-80h160q83 0 141.5 58.5T880-480q0 83-58.5 141.5T680-280H520Z"/></svg>)SVG";

    // Material Symbols "view_quilt" (Memory map)
    static const char icons_memory_map_svg[] =
        R"SVG(<svg width="16px" height="16px" viewBox="0 -960 960 960" fill="#e3e3e3" xmlns="http://www.w3.org/2000/svg"><path d="M120-280v-400q0-33 23.5-56.5T200-760h560q33 0 56.5 23.5T840-680v400q0 33-23.5 56.5T760-200H200q-33 0-56.5-23.5T120-280Zm293-240h347v-160H413v160Zm214 240h133v-160H627v160Zm-214 0h134v-160H413v160Zm-213 0h133v-400H200v400Z"/></svg>)SVG";
}
