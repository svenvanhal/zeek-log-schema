type GlobalRecord: record {
    field1: string &log;
};

type global::NamespacedGlobalRecord: record {
    field2: string &log;
};

export {
    type ExportedGlobalRecord: record {
        field3: string &log;
    };

    type global::NamespacedExportedGlobalRecord: record {
        field4: string &log;
    };
}

module Test;

type ScopedRecord: record {
    field5: string &log;
};

type Test::NamespacedScopedRecord: record {
    field6: string &log;
};

export {
    type ExportedScopedRecord: record {
        field7: string &log;
    };

    type Test::NamespacedExportedScopedRecord: record {
        field8: string &log;
    };
}

module SecondTest;

type SwitchScopedRecord: record {
    field9: string &log;
};

type Test::NamespacedSwitchScopedRecord: record {
    field10: string &log;
};

export {
    type ExportedSwitchScopedRecord: record {
        field11: string &log;
    };

    type SecondTest::NamespacedExportedSwitchScopedRecord: record {
        field12: string &log;
    };

    type Test::NamespacedExportedDifferentScopedRecord: record {
        field13: string &log;
    };
}

module GLOBAL;

type SwitchGlobalRecord: record {
    field1: string &log;
};

type global::NamespacedSwitchGlobalRecord: record {
    field2: string &log;
};

export {
    type ExportedSwitchGlobalRecord: record {
        field3: string &log;
    };

    type global::NamespacedExportedSwitchGlobalRecord: record {
        field4: string &log;
    };

    type Test::GlobalNamespacedExportedDifferentScopedRecord: record {
        field13: string &log;
    };
}

module Comment;
export {

    ## Record Comment
    type CommentedRecord: record {
        ## FieldComment
        field14: string &log;
    };
}
