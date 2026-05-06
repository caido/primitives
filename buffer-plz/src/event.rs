use crate::Cursor;

// Event's created by the IO
pub enum Event<'a, 'b> {
    Read(&'a mut Cursor<'b>),
    End(&'a mut Cursor<'b>),
}

impl<'a, 'b> AsMut<Event<'a, 'b>> for Event<'a, 'b> {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<'a, 'b> Event<'a, 'b> {
    pub fn inner_mut(&mut self) -> &mut Cursor<'b> {
        match self {
            Event::Read(cursor) | Event::End(cursor) => cursor,
        }
    }
}
