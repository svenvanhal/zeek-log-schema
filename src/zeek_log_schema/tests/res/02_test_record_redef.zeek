export {
    ## The internal data structure for the queue.
	type Queue: record {};
}

redef record Queue += {
	# Indicator for if the queue was appropriately initialized.
	initialized: bool                   &default=F;
	# The values are stored here.
	vals:        table[count] of any &optional;
	# Settings for the queue.
	settings:    Settings               &optional;
	# The top value in the vals table.
	top:         count                  &default=0;
	# The bottom value in the vals table.
	bottom:      count                  &default=0;
	# The number of bytes in the queue.
	size:        count                  &default=0;
};
